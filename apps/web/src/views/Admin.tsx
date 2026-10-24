// Usage, pairing codes, devices, and the shared host list.

import { useEffect, useState } from "preact/hooks";
import { Healthy } from "../icons";
import { ApiError, json } from "../lib/api";
import { bytes, when } from "../lib/format";
import { Modal, useApp } from "./Shell";

interface Usage {
  stored_bytes: number;
  unreferenced_bytes: number;
  disk_free?: number;
  disk_total?: number;
  version: string;
  uptime_secs: number;
}

interface Device {
  id: string;
  name: string;
  created_at: number;
  last_seen_ms: number | null;
  online: boolean;
  current: boolean;
}

export interface Host {
  name: string;
  url: string;
  ssids: string[];
}

function uptime(secs: number): string {
  const d = Math.floor(secs / 86400);
  if (d >= 1) return `Up ${d} ${d === 1 ? "day" : "days"}`;
  const h = Math.floor(secs / 3600);
  if (h >= 1) return `Up ${h} h`;
  return `Up ${Math.max(1, Math.floor(secs / 60))} min`;
}

export function Admin() {
  const { session, dialog } = useApp();
  const [usage, setUsage] = useState<Usage>();
  const [devices, setDevices] = useState<Device[]>([]);
  const [failed, setFailed] = useState("");

  const load = async () => {
    try {
      const [u, d] = await Promise.all([session.api.call("GET", "/v1/usage"), session.api.call("GET", "/v1/devices")]);
      setUsage(json(u));
      setDevices(json(d));
      setFailed("");
    } catch (e) {
      setFailed((e as Error).message);
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, [session]);

  const totals = session.shelf.totals() as { files: number; folders: number; bytes: number };
  const used = usage?.disk_total ? usage.disk_total - (usage.disk_free ?? 0) : undefined;
  const online = devices.filter((d) => d.online).length;

  async function cleanup() {
    try {
      const r = json(await session.api.call("POST", "/v1/gc"));
      await load();
      await dialog.alert("Cleanup done", r.removed_chunks ? `Freed ${r.removed_chunks} chunks.` : "Nothing old enough to remove yet.");
    } catch (e) {
      await dialog.alert("Cleanup failed", (e as Error).message);
    }
  }

  return (
    <main class="admin">
      <h1>Your shelf</h1>
      {failed && <div class="banner err">{failed}</div>}
      <div class="tiles">
        <div class="tile">
          <span class="tl">Storage used</span>
          <span class="tv">{used !== undefined ? bytes(used) : usage ? bytes(usage.stored_bytes) : "…"}</span>
          <span class="ts">
            {usage?.disk_total ? `of ${bytes(usage.disk_total)} · ${bytes(usage.disk_free ?? 0)} free` : " "}
          </span>
        </div>
        <div class="tile">
          <span class="tl">Files</span>
          <span class="tv">{totals.files.toLocaleString()}</span>
          <span class="ts">
            in {totals.folders.toLocaleString()} {totals.folders === 1 ? "folder" : "folders"}
          </span>
        </div>
        <div class="tile">
          <span class="tl">Devices</span>
          <span class="tv">{devices.length || "…"}</span>
          <span class="ts">{online} online now</span>
        </div>
        <div class="tile">
          <span class="tl">Server</span>
          <span class="tv">
            {usage ? (
              <>
                <Healthy />
                Healthy
              </>
            ) : (
              "…"
            )}
          </span>
          <span class="ts">{usage ? `${uptime(usage.uptime_secs)} · oshelfd ${usage.version}` : " "}</span>
        </div>
      </div>

      <div class="cols">
        <SpaceSection usage={usage} onCleanup={cleanup} />
        <PairSection />
      </div>

      <DevicesSection devices={devices} reload={load} />
      <HostsSection />
    </main>
  );
}

function SpaceSection({ usage, onCleanup }: { usage?: Usage; onCleanup: () => void }) {
  const { session } = useApp();
  const top = session.list("");
  const rows = top
    .filter((n) => n.kind === "dir")
    .map((n) => ({ name: n.name, bytes: n.total }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 8);
  const loose = top.filter((n) => n.kind === "file").reduce((a, n) => a + n.size, 0);
  if (loose) rows.push({ name: "Files at the top", bytes: loose });
  const max = Math.max(1, ...rows.map((r) => r.bytes), usage?.unreferenced_bytes ?? 0);
  return (
    <section class="section" style={{ flex: "1 1 520px" }}>
      <h2>Where the space goes</h2>
      <div class="bars">
        {rows.length === 0 && <span class="muted">Nothing on the shelf yet.</span>}
        {rows.map((r) => (
          <div class="br" key={r.name} title={`${r.name}: ${bytes(r.bytes)}`}>
            <span>{r.name}</span>
            <span class="trk" style={{ width: `${(r.bytes / max) * 100}%` }} />
            <span>{bytes(r.bytes)}</span>
          </div>
        ))}
        {usage && usage.unreferenced_bytes > 0 && (
          <div class="br" title="Old versions and deleted files waiting for cleanup">
            <span>Waiting for cleanup</span>
            <span class="trk" style={{ width: `${(usage.unreferenced_bytes / max) * 100}%`, background: "var(--muted-bar)" }} />
            <span>{bytes(usage.unreferenced_bytes)}</span>
          </div>
        )}
      </div>
      <div style={{ display: "flex", borderTop: "1px solid var(--line)", paddingTop: 14 }}>
        <button type="button" class="btn" style={{ marginLeft: "auto" }} onClick={onCleanup}>
          Run cleanup
        </button>
      </div>
    </section>
  );
}

function PairSection() {
  const { session, dialog } = useApp();
  const [code, setCode] = useState<{ code: string; expires_at: number }>();
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (!code) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [code]);

  const left = code ? Math.max(0, code.expires_at * 1000 - now) : 0;
  useEffect(() => {
    if (code && left === 0) setCode(undefined);
  }, [left]);

  async function make() {
    try {
      setCode(json(await session.api.call("POST", "/v1/pairing-codes")));
      setNow(Date.now());
    } catch (e) {
      await dialog.alert("Couldn't make a code", (e as Error).message);
    }
  }

  async function cancel() {
    if (!code) return;
    await session.api.call("DELETE", `/v1/pairing-codes/${code.code.replace(/[^0-9A-Z]/gi, "")}`, { allow: [404] }).catch(() => undefined);
    setCode(undefined);
  }

  const mins = Math.floor(left / 60000);
  const secs = Math.floor((left % 60000) / 1000);
  return (
    <section class="section" style={{ flex: "1 1 340px" }}>
      <h2>Pair a device</h2>
      <p class="muted" style={{ margin: 0, fontSize: 13, lineHeight: 1.55 }}>
        Enter on the new Mac or browser. Single use.
      </p>
      {code && (
        <div class="code-box" aria-live="polite">
          <code>{code.code}</code>
          <span style={{ fontSize: 12 }}>
            Expires in {mins}:{String(secs).padStart(2, "0")}
          </span>
        </div>
      )}
      <div class="row-btns">
        <button type="button" class={`btn${code ? "" : " primary"}`} onClick={make}>
          New code
        </button>
        {code && (
          <button type="button" class="btn" onClick={cancel}>
            Cancel code
          </button>
        )}
      </div>
    </section>
  );
}

function DevicesSection({ devices, reload }: { devices: Device[]; reload: () => void }) {
  const { session, dialog, lock } = useApp();

  async function revoke(d: Device) {
    const ok = await dialog.confirm(`Revoke ${d.name}?`, "It loses access right away and has to be paired again.", "Revoke");
    if (!ok) return;
    try {
      await session.api.call("DELETE", `/v1/devices/${d.id}`);
      reload();
    } catch (e) {
      await dialog.alert("Couldn't revoke", (e as Error).message);
    }
  }

  return (
    <section class="section">
      <h2>Devices</h2>
      <div style={{ overflowX: "auto" }}>
        <table class="devices">
          <thead>
            <tr>
              <th>Device</th>
              <th>Last seen</th>
              <th>Paired</th>
              <th>
                <span class="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id}>
                <td>
                  <strong style={{ fontWeight: 600 }}>{d.current ? "This browser" : d.name}</strong>
                  <br />
                  <span class="muted" style={{ fontSize: 12 }}>
                    {d.current ? d.name : `key …${d.id.slice(-4).toUpperCase()}`}
                  </span>
                </td>
                <td>
                  {d.current ? (
                    <span class="pill">Now</span>
                  ) : d.online ? (
                    <span class="pill" style={{ background: "var(--mist)", color: "var(--accent)" }}>
                      Online now
                    </span>
                  ) : (
                    <span class="muted">{d.last_seen_ms ? when(d.last_seen_ms) : "Not since the Pi restarted"}</span>
                  )}
                </td>
                <td class="muted">{when(d.created_at * 1000)}</td>
                <td style={{ textAlign: "right" }}>
                  {d.current ? (
                    <button type="button" class="btn small" onClick={lock}>
                      Lock
                    </button>
                  ) : (
                    <button type="button" class="btn small danger-outline" onClick={() => revoke(d)}>
                      Revoke…
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function HostsSection() {
  const { session, dialog } = useApp();
  const [hosts, setHosts] = useState<Host[]>();
  const [etag, setEtag] = useState<string>();
  const [editing, setEditing] = useState<{ index: number; host: Host }>();
  const [error, setError] = useState("");

  async function load() {
    try {
      const r = await session.api.call("GET", "/v1/hosts", { allow: [404] });
      if (r.status === 404) {
        setHosts([]);
        setEtag(undefined);
      } else {
        setHosts(JSON.parse(session.shelf.open_hosts(r.body)));
        setEtag((r.headers.get("etag") ?? "").replaceAll('"', ""));
      }
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }

  useEffect(() => {
    load();
  }, [session]);

  async function save(next: Host[]) {
    try {
      const r = await session.api.call("PUT", "/v1/hosts", {
        body: session.shelf.seal_hosts(JSON.stringify(next)),
        headers: etag ? { "if-match": etag } : {},
      });
      setHosts(next);
      setEtag((r.headers.get("etag") ?? "").replaceAll('"', ""));
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        await dialog.alert("Changed on another device", "The host list was edited elsewhere. Here's the latest; make your change again.");
        await load();
      } else {
        await dialog.alert("Couldn't save", (e as Error).message);
      }
    }
  }

  const list = hosts ?? [];
  const move = (i: number, by: number) => {
    const next = [...list];
    const [h] = next.splice(i, 1);
    next.splice(i + by, 0, h);
    save(next);
  };

  return (
    <section class="section">
      <div class="hd">
        <h2>Hosts and Wi-Fi rules</h2>
        <button
          type="button"
          class="btn"
          onClick={() => setEditing({ index: -1, host: { name: "", url: list.length ? "" : location.origin, ssids: [] } })}
          disabled={!hosts}
        >
          Add host
        </button>
      </div>
      <p class="muted" style={{ margin: 0, fontSize: 13 }}>
        First match wins. Shared with every Mac.
      </p>
      {error && <div class="banner err">{error}</div>}
      <div>
        {hosts && list.length === 0 && <span class="muted" style={{ fontSize: 13 }}>No hosts yet. Macs use the address they paired with.</span>}
        {list.map((h, i) => (
          <div class="hostrow" key={`${i}:${h.url}`}>
            <strong>
              {i + 1} · {h.name}
            </strong>
            <span class="muted" style={{ overflowWrap: "anywhere" }}>
              {h.url}
            </span>
            {h.ssids.length ? (
              h.ssids.map((s) => (
                <span class="pill" key={s}>
                  Wi-Fi is {s}
                </span>
              ))
            ) : (
              <span class="pill">Anywhere else</span>
            )}
            <span class="acts">
              <button type="button" class="btn small" aria-label={`Move ${h.name} up`} disabled={i === 0} onClick={() => move(i, -1)}>
                ↑
              </button>
              <button type="button" class="btn small" aria-label={`Move ${h.name} down`} disabled={i === list.length - 1} onClick={() => move(i, 1)}>
                ↓
              </button>
              <button type="button" class="btn small" onClick={() => setEditing({ index: i, host: h })}>
                Edit
              </button>
            </span>
          </div>
        ))}
      </div>
      {editing && (
        <HostDialog
          host={editing.host}
          isNew={editing.index < 0}
          onClose={() => setEditing(undefined)}
          onSave={(h) => {
            const next = [...list];
            if (editing.index < 0) next.push(h);
            else next[editing.index] = h;
            setEditing(undefined);
            save(next);
          }}
          onRemove={() => {
            setEditing(undefined);
            save(list.filter((_, j) => j !== editing.index));
          }}
        />
      )}
    </section>
  );
}

function HostDialog(p: { host: Host; isNew: boolean; onClose: () => void; onSave: (h: Host) => void; onRemove: () => void }) {
  const [name, setName] = useState(p.host.name);
  const [url, setUrl] = useState(p.host.url);
  const [ssids, setSsids] = useState(p.host.ssids.join(", "));
  let valid = false;
  try {
    valid = /^https?:$/.test(new URL(url).protocol) && name.trim().length > 0;
  } catch {
    valid = false;
  }
  return (
    <Modal onCancel={p.onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          p.onSave({
            name: name.trim(),
            url: url.trim().replace(/\/+$/, ""),
            ssids: ssids
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean),
          });
        }}
      >
        <span class="t">{p.isNew ? "Add host" : "Edit host"}</span>
        <div class="field">
          <label for="h-name">Name</label>
          <input id="h-name" class="input" placeholder="Home" value={name} onInput={(e) => setName(e.currentTarget.value)} required />
        </div>
        <div class="field">
          <label for="h-url">Address</label>
          <input
            id="h-url"
            class="input"
            placeholder="http://192.168.1.20:8740"
            inputMode="url"
            spellcheck={false}
            value={url}
            onInput={(e) => setUrl(e.currentTarget.value)}
            required
          />
        </div>
        <div class="field">
          <label for="h-ssid">Wi-Fi names</label>
          <input id="h-ssid" class="input" placeholder="Home-5G, Home-2G" value={ssids} onInput={(e) => setSsids(e.currentTarget.value)} />
          <span class="muted" style={{ fontSize: 12 }}>
            Leave empty to use it anywhere, like a tunnel.
          </span>
        </div>
        <div class="acts">
          {!p.isNew && (
            <button type="button" class="btn danger" style={{ marginRight: "auto" }} onClick={p.onRemove}>
              Remove
            </button>
          )}
          <button type="button" class="btn" onClick={p.onClose}>
            Cancel
          </button>
          <button class="btn primary" disabled={!valid}>
            Save
          </button>
        </div>
      </form>
    </Modal>
  );
}
