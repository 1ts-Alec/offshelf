// First-run setup, right after pairing: pick the drive the shelf lives on,
// then lock it with a passphrase and show the recovery key once.

import { useEffect, useState } from "preact/hooks";
import { json, type Api } from "../lib/api";
import { createVault, type NewVault } from "../lib/kdf";
import { bytes as formatBytes } from "../lib/format";
import { CenterCard } from "./Gate";

export interface Drive {
  path: string;
  folder: string;
  fs: string;
  device: string;
  total: number;
  free: number;
  current: boolean;
  unusable?: string;
}

export interface StorageInfo {
  configured: boolean;
  current: string;
  drives: Drive[];
  recommended?: string;
  moving?: { to: string; copied: number; total: number; error?: string };
}

export async function loadStorage(api: Api): Promise<StorageInfo> {
  return json<StorageInfo>(await api.call("GET", "/v1/storage"));
}

function driveName(d: Drive): string {
  return d.path === "/" ? "This server's main disk" : d.path;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Step 1: where the shelf lives. */
export function ChooseDrive({ api, info, onDone }: { api: Api; info: StorageInfo; onDone: () => void }) {
  const [pick, setPick] = useState(info.recommended ?? info.drives.find((d) => d.current)?.path ?? "/");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const [error, setError] = useState("");

  async function use(e: Event) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.call("POST", "/v1/storage", { body: JSON.stringify({ drive: pick }), headers: { "content-type": "application/json" } });
      // The server copies its data, then restarts on the drive. Wait for it
      // to come back configured.
      setNote("Setting up your shelf…");
      for (let i = 0; i < 300; i++) {
        await sleep(1000);
        try {
          const s = await loadStorage(api);
          if (s.moving?.error) throw new Error(s.moving.error);
          if (s.configured && !s.moving) return onDone();
        } catch (err) {
          if ((err as Error).message && !/fetch|network|reach|Offline/i.test((err as Error).message)) throw err;
          setNote("Restarting on the new drive…");
        }
      }
      throw new Error("The server didn't come back. Check it's running, then reload.");
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
      setNote("");
    }
  }

  return (
    <CenterCard>
      <form class="card setup" onSubmit={use}>
        <h1>Where should your shelf live?</h1>
        <p>Pick a drive. Offshelf keeps everything in an offshelf folder on it.</p>
        <div class="drives" role="radiogroup" aria-label="Drives">
          {info.drives.map((d) => {
            const used = d.total ? 1 - d.free / d.total : 0;
            return (
              <label class={"drive" + (pick === d.path ? " on" : "") + (d.unusable ? " off" : "")}>
                <input
                  type="radio"
                  name="drive"
                  value={d.path}
                  checked={pick === d.path}
                  disabled={!!d.unusable || busy}
                  onChange={() => setPick(d.path)}
                />
                <span class="drive-body">
                  <span class="drive-top">
                    <span class="drive-name">{driveName(d)}</span>
                    {d.path === info.recommended && <span class="pill">Recommended</span>}
                    {d.current && info.configured && <span class="pill quiet">In use</span>}
                  </span>
                  <span class="drive-meta">
                    {d.unusable ?? `${formatBytes(d.free)} free of ${formatBytes(d.total)} · ${d.fs === "system" ? d.folder : d.fs}`}
                  </span>
                  {!d.unusable && (
                    <span class="drive-bar" aria-hidden="true">
                      <span style={{ width: `${Math.round(used * 100)}%` }} />
                    </span>
                  )}
                </span>
              </label>
            );
          })}
        </div>
        {error && (
          <span class="error-line" role="alert">
            {error}
          </span>
        )}
        <button class="btn primary big" disabled={busy}>
          {busy ? note || "Working…" : "Use this drive"}
        </button>
      </form>
    </CenterCard>
  );
}

/** Step 2: the passphrase, then the recovery key, shown once. */
export function CreateShelf({ api, onDone }: { api: Api; onDone: (v: NewVault) => Promise<void> }) {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [made, setMade] = useState<NewVault>();
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);

  async function create(e: Event) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const v = await createVault(a);
      await api.call("PUT", "/v1/vault", { body: v.header });
      setA("");
      setB("");
      setMade(v);
    } catch (err) {
      setError((err as Error).message);
    }
    setBusy(false);
  }

  async function finish(e: Event) {
    e.preventDefault();
    setBusy(true);
    try {
      await onDone(made!);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  useEffect(() => setCopied(false), [made]);

  if (made) {
    const words = made.words.split(" ");
    return (
      <CenterCard>
        <form class="card setup" onSubmit={finish}>
          <h1>Your recovery key</h1>
          <p>The only way back in if you forget your passphrase. Shown once.</p>
          <ol class="words">
            {words.map((w) => (
              <li class="mono">{w}</li>
            ))}
          </ol>
          <div class="row-btns">
            <button
              type="button"
              class="btn"
              onClick={async () => {
                await navigator.clipboard.writeText(made.words);
                setCopied(true);
              }}
            >
              {copied ? "Copied" : "Copy"}
            </button>
            <button type="button" class="btn" onClick={() => window.print()}>
              Print
            </button>
          </div>
          <label class="check">
            <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.currentTarget.checked)} />
            I've saved my recovery key somewhere safe
          </label>
          {error && (
            <span class="error-line" role="alert">
              {error}
            </span>
          )}
          <button class="btn primary big" disabled={!saved || busy}>
            {busy ? "Opening…" : "Open my shelf"}
          </button>
        </form>
      </CenterCard>
    );
  }

  return (
    <CenterCard>
      <form class="card setup" onSubmit={create}>
        <h1>Lock your shelf</h1>
        <p>Everything is encrypted with this. It never leaves your devices.</p>
        <div class="field">
          <label for="sp1">Passphrase</label>
          <input id="sp1" class="input" type="password" autocomplete="new-password" minLength={8} value={a} onInput={(e) => setA(e.currentTarget.value)} required />
        </div>
        <div class="field">
          <label for="sp2">Type it again</label>
          <input
            id="sp2"
            class="input"
            type="password"
            autocomplete="new-password"
            value={b}
            onInput={(e) => setB(e.currentTarget.value)}
            aria-invalid={b.length > 0 && a !== b ? "true" : undefined}
            required
          />
        </div>
        {error && (
          <span class="error-line" role="alert">
            {error}
          </span>
        )}
        <button class="btn primary big" disabled={busy || a.length < 8 || a !== b}>
          {busy ? "Locking… (a few seconds)" : "Create shelf"}
        </button>
      </form>
    </CenterCard>
  );
}
