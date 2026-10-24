// Everything before the shelf is open: pairing this browser, unlocking with
// the passphrase or recovery words, and the first tree load.

import { useState } from "preact/hooks";
import type { ComponentChildren } from "preact";
import { Alert, Mark } from "../icons";
import { browserName } from "../lib/format";

function Brand() {
  return (
    <div class="brand">
      <Mark size={32} />
      <span>Offshelf</span>
    </div>
  );
}

export function CenterCard({ children }: { children: ComponentChildren }) {
  return (
    <div class="center">
      <Brand />
      {children}
    </div>
  );
}

function ErrorLine({ id, text }: { id: string; text: string }) {
  return (
    <span id={id} class="error-line" role="alert">
      <Alert />
      {text}
    </span>
  );
}

export function Pair({ onPair }: { onPair: (code: string, name: string) => Promise<void> }) {
  const [code, setCode] = useState("");
  const [name, setName] = useState(browserName());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(e: Event) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onPair(code, name.trim() || browserName());
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <CenterCard>
      <form class="card" onSubmit={submit}>
        <h1>Pair this browser</h1>
        <p>Make a code on a paired Mac, or run oshelfd pair on the Pi.</p>
        <div class="field">
          <label for="code">Pairing code</label>
          <input
            id="code"
            class="input mono"
            autocomplete="one-time-code"
            autocapitalize="characters"
            spellcheck={false}
            placeholder="XXXX-XXXX"
            value={code}
            onInput={(e) => setCode(e.currentTarget.value)}
            aria-invalid={error ? "true" : undefined}
            aria-describedby={error ? "pair-err" : undefined}
            required
          />
        </div>
        <div class="field">
          <label for="dname">Name</label>
          <input id="dname" class="input" value={name} maxLength={64} onInput={(e) => setName(e.currentTarget.value)} />
        </div>
        {error && <ErrorLine id="pair-err" text={error} />}
        <button class="btn primary big" disabled={busy || code.replace(/[^0-9a-z]/gi, "").length < 8}>
          {busy ? "Pairing…" : "Pair"}
        </button>
        <div class="card-foot">
          <span>{location.host}</span>
        </div>
      </form>
    </CenterCard>
  );
}

export interface UnlockProps {
  deviceName: string;
  onUnlock: (secret: string, recovery: boolean, stay: boolean) => Promise<void>;
  onForget: () => void;
}

export function Unlock({ deviceName, onUnlock, onForget }: UnlockProps) {
  const [recovery, setRecovery] = useState(false);
  const [secret, setSecret] = useState("");
  const [stay, setStay] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(e: Event) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onUnlock(secret, recovery, stay);
    } catch (err) {
      const m = (err as Error).message;
      setError(
        /wrong|authentication/i.test(m)
          ? recovery
            ? "Those words didn't unlock this shelf."
            : "That passphrase didn't unlock this shelf. Check caps lock and try again."
          : /recovery words/i.test(m)
            ? "Those aren't valid recovery words. Check each one."
            : m,
      );
      setBusy(false);
    }
  }

  function toggle() {
    setRecovery(!recovery);
    setSecret("");
    setError("");
  }

  return (
    <CenterCard>
      <form class="card" onSubmit={submit}>
        <h1>{recovery ? "Use your recovery key" : "Unlock your shelf"}</h1>
        <p>{recovery ? "Then set a new passphrase." : "Decrypted in your browser. Your passphrase never leaves it."}</p>
        {recovery ? (
          <div class="field">
            <label for="rk">Recovery words</label>
            <textarea
              id="rk"
              class="input mono"
              rows={4}
              spellcheck={false}
              autocapitalize="off"
              value={secret}
              onInput={(e) => setSecret(e.currentTarget.value)}
              aria-invalid={error ? "true" : undefined}
              aria-describedby={error ? "ul-err" : undefined}
              required
            />
          </div>
        ) : (
          <div class="field">
            <label for="pp">Passphrase</label>
            <input
              id="pp"
              class="input"
              type="password"
              autocomplete="current-password"
              value={secret}
              onInput={(e) => setSecret(e.currentTarget.value)}
              aria-invalid={error ? "true" : undefined}
              aria-describedby={error ? "ul-err" : undefined}
              autofocus
              required
            />
          </div>
        )}
        <label class="check">
          <input type="checkbox" checked={stay} onChange={(e) => setStay(e.currentTarget.checked)} />
          <span>Stay unlocked for 7 days</span>
        </label>
        {error && <ErrorLine id="ul-err" text={error} />}
        <button class="btn primary big" disabled={busy || !secret}>
          {busy ? "Unlocking…" : recovery ? "Continue" : "Unlock"}
        </button>
        <div class="card-foot">
          <span>
            {location.host} · {deviceName}
          </span>
          <span style={{ display: "flex", gap: 12 }}>
            <button type="button" class="linkish" onClick={toggle}>
              {recovery ? "Use passphrase" : "Use recovery key"}
            </button>
            <button type="button" class="linkish" onClick={onForget}>
              Unpair
            </button>
          </span>
        </div>
      </form>
    </CenterCard>
  );
}

export function NewPassphrase({ onSave }: { onSave: (p: string) => Promise<void> }) {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const mismatch = b.length > 0 && a !== b;

  async function submit(e: Event) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onSave(a);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  }

  return (
    <CenterCard>
      <form class="card" onSubmit={submit}>
        <h1>Set a new passphrase</h1>
        <p>Your Macs ask for it next time they unlock.</p>
        <div class="field">
          <label for="np1">New passphrase</label>
          <input id="np1" class="input" type="password" autocomplete="new-password" minLength={8} value={a} onInput={(e) => setA(e.currentTarget.value)} required />
        </div>
        <div class="field">
          <label for="np2">Again</label>
          <input
            id="np2"
            class="input"
            type="password"
            autocomplete="new-password"
            value={b}
            onInput={(e) => setB(e.currentTarget.value)}
            aria-invalid={mismatch ? "true" : undefined}
            required
          />
        </div>
        {error && <ErrorLine id="np-err" text={error} />}
        <button class="btn primary big" disabled={busy || a.length < 8 || a !== b}>
          {busy ? "Saving…" : "Save"}
        </button>
      </form>
    </CenterCard>
  );
}

export function Loading({ loaded, total }: { loaded: number; total: number }) {
  const pct = total ? Math.round((loaded / total) * 100) : 0;
  return (
    <CenterCard>
      <div class="card" aria-busy="true">
        <h1>{total ? "Decrypting your file tree" : "Unlocking"}</h1>
        <div class="bar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
          <span style={{ width: `${total ? pct : 8}%` }} />
        </div>
        {total > 0 && (
          <span class="muted" style={{ fontSize: 13 }}>
            {loaded} of {total} MB
          </span>
        )}
      </div>
    </CenterCard>
  );
}

export function Problem({ title, text, action }: { title: string; text: string; action?: ComponentChildren }) {
  return (
    <CenterCard>
      <div class="card">
        <h1>{title}</h1>
        <p>{text}</p>
        {action}
      </div>
    </CenterCard>
  );
}
