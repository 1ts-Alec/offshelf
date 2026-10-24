// The unlocked app: header, routes, upload and download toasts, dialogs.

import { createContext, type ComponentChildren } from "preact";
import { useContext, useEffect, useRef, useState } from "preact/hooks";
import { Lock, Mark, NoWifi, Search, Up, Warn, Down } from "../icons";
import { bytes, clock } from "../lib/format";
import type { NodeView, Session, UploadProgress } from "../lib/session";
import { Files } from "./Files";
import { Preview } from "./Preview";

// ---- routing ----------------------------------------------------------------

export type Route = { view: "files"; dir: string } | { view: "preview"; id: string } | { view: "admin" };

function parse(hash: string): Route {
  const [, view, arg] = hash.replace(/^#/, "").split("/");
  if (view === "p" && arg) return { view: "preview", id: arg };
  if (view === "admin") return { view: "admin" };
  return { view: "files", dir: view === "f" && arg ? arg : "" };
}

export const href = {
  dir: (id: string) => (id && !/^0+$/.test(id) ? `#/f/${id}` : "#/"),
  preview: (id: string) => `#/p/${id}`,
  admin: "#/admin",
};

function useRoute(): Route {
  const [hash, setHash] = useState(location.hash);
  useEffect(() => {
    const f = () => setHash(location.hash);
    addEventListener("hashchange", f);
    return () => removeEventListener("hashchange", f);
  }, []);
  return parse(hash);
}

/** Re-renders whenever the tree or connection status changes. */
function useSession(s: Session) {
  const [, tick] = useState(0);
  useEffect(() => s.subscribe(() => tick((n) => n + 1)), [s]);
}

// ---- jobs: uploads and downloads ---------------------------------------------

interface UploadJob {
  key: number;
  kind: "upload";
  parent: string;
  files: File[];
  progress: UploadProgress;
  finished: boolean;
}

interface DownloadJob {
  key: number;
  kind: "download";
  name: string;
  size: number;
  bytes: number;
  error?: string;
}

type Job = UploadJob | DownloadJob;

export interface AppCtx {
  session: Session;
  upload(parent: string, files: File[]): void;
  download(node: NodeView): void;
  dialog: DialogApi;
}

export const Ctx = createContext<AppCtx>(null as unknown as AppCtx);
export const useApp = () => useContext(Ctx);

let jobKey = 0;

export function Shell({ session, onLock }: { session: Session; onLock: () => void }) {
  useSession(session);
  const route = useRoute();
  const [query, setQuery] = useState("");
  const [jobs, setJobs] = useState<Job[]>([]);
  const dialog = useDialogs();

  const update = (key: number, f: (j: Job) => Job) => setJobs((js) => js.map((j) => (j.key === key ? f(j) : j)));
  const dismiss = (key: number) => setJobs((js) => js.filter((j) => j.key !== key));

  function upload(parent: string, files: File[]) {
    if (!files.length) return;
    const key = ++jobKey;
    const total = files.reduce((a, f) => a + f.size, 0);
    setJobs((js) => [
      ...js,
      { key, kind: "upload", parent, files, finished: false, progress: { files: files.length, done: 0, bytes: 0, total, failed: [] } },
    ]);
    session
      .upload(parent, files, (p) => update(key, (j) => ({ ...j, progress: p })))
      .then((p) => {
        update(key, (j) => ({ ...j, progress: p, finished: true }));
        if (!p.failed.length) setTimeout(() => dismiss(key), 2500);
      });
  }

  function download(node: NodeView) {
    const key = ++jobKey;
    setJobs((js) => [...js, { key, kind: "download", name: node.name, size: node.size, bytes: 0 }]);
    session
      .readFile(node.id, (b) => update(key, (j) => ({ ...j, bytes: b })))
      .then((blob) => {
        save(blob, node.name);
        dismiss(key);
      })
      .catch((e) => update(key, (j) => ({ ...j, error: (e as Error).message })));
  }

  const busy = jobs.some((j) => j.kind === "upload" && !j.finished);
  useEffect(() => {
    if (!busy) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    addEventListener("beforeunload", warn);
    return () => removeEventListener("beforeunload", warn);
  }, [busy]);

  const ctx: AppCtx = { session, upload, download, dialog: dialog.api };

  return (
    <Ctx.Provider value={ctx}>
      {route.view !== "preview" && (
        <header class="top">
          <a class="brand" href="#/">
            <Mark />
            <span>Offshelf</span>
          </a>
          <nav aria-label="Main" class="tabs">
            <a class="tab" href="#/" aria-current={route.view === "files" ? "page" : undefined}>
              Files
            </a>
            <a class="tab" href={href.admin} aria-current={route.view === "admin" ? "page" : undefined}>
              Admin
            </a>
          </nav>
          {route.view === "files" && (
            <label class="search">
              <Search />
              <input type="search" aria-label="Search the shelf" placeholder="Search the shelf" value={query} onInput={(e) => setQuery(e.currentTarget.value)} />
            </label>
          )}
          <StatusPill session={session} />
          <button class="btn" onClick={onLock}>
            <Lock />
            Lock
          </button>
        </header>
      )}
      {session.status === "offline" && route.view !== "preview" && (
        <div style={{ padding: "16px 24px 0", maxWidth: 1440, margin: "0 auto" }}>
          <div class="banner">
            <NoWifi />
            <span>
              <strong>Lost connection to your shelf.</strong> Retrying…
            </span>
            <button class="btn small" onClick={() => session.verify().catch(() => undefined)}>
              Try now
            </button>
          </div>
        </div>
      )}
      {route.view === "files" && <Files dir={route.dir} query={query} clearQuery={() => setQuery("")} />}
      {route.view === "preview" && <Preview id={route.id} />}
      {route.view === "admin" && <AdminPlaceholder />}
      <Toasts jobs={jobs} dismiss={dismiss} retry={(j) => (dismiss(j.key), upload(j.parent, j.files.filter((f) => j.progress.failed.some((x) => x.name === f.name))))} />
      {dialog.element}
    </Ctx.Provider>
  );
}

function AdminPlaceholder() {
  return (
    <main class="admin">
      <h1>Your shelf</h1>
    </main>
  );
}

export function StatusPill({ session }: { session: Session }) {
  if (session.status === "live") {
    return (
      <span class="pill live">
        <span class="dot" />
        Live
      </span>
    );
  }
  if (session.status === "offline") {
    return (
      <span class="pill live offline" title={`Last verified ${clock(session.lastVerified)}`}>
        <Warn />
        May be out of date · {clock(session.lastVerified)}
      </span>
    );
  }
  return (
    <span class="pill live connecting">
      <span class="dot" />
      Connecting
    </span>
  );
}

function Toasts({ jobs, dismiss, retry }: { jobs: Job[]; dismiss: (k: number) => void; retry: (j: UploadJob) => void }) {
  if (!jobs.length) return null;
  return (
    <div class="toasts" aria-live="polite">
      {jobs.map((j) => {
        if (j.kind === "download") {
          const pct = j.size ? (j.bytes / j.size) * 100 : 100;
          return (
            <div class={`toast${j.error ? " err" : ""}`} key={j.key}>
              <div class="row">
                <Down />
                <strong>{j.error ? `Couldn't download ${j.name}` : `Decrypting ${j.name}`}</strong>
              </div>
              {j.error ? (
                <>
                  <span>{j.error}</span>
                  <div class="acts">
                    <button class="btn small" onClick={() => dismiss(j.key)}>
                      Dismiss
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <div class="bar">
                    <span style={{ width: `${pct}%` }} />
                  </div>
                  <span class="muted">
                    {bytes(j.bytes)} of {bytes(j.size)}
                  </span>
                </>
              )}
            </div>
          );
        }
        const p = j.progress;
        if (j.finished && p.failed.length) {
          return (
            <div class="toast err" key={j.key}>
              <strong>
                {p.failed.length} of {p.files} {p.files === 1 ? "file" : "files"} didn't upload
              </strong>
              <span>{p.failed.map((f) => f.name).join(", ")}</span>
              <span>{p.failed[0].error}</span>
              <div class="acts">
                <button class="btn small primary" onClick={() => retry(j)}>
                  Retry {p.failed.length === 1 ? "" : `${p.failed.length} files`}
                </button>
                <button class="btn small" onClick={() => dismiss(j.key)}>
                  Dismiss
                </button>
              </div>
            </div>
          );
        }
        const pct = p.total ? (p.bytes / p.total) * 100 : j.finished ? 100 : 0;
        return (
          <div class="toast" key={j.key}>
            <div class="row">
              <Up />
              <strong>
                {j.finished ? "Uploaded" : "Encrypting and uploading"} {p.files} {p.files === 1 ? "file" : "files"}
              </strong>
            </div>
            <div class="bar">
              <span style={{ width: `${pct}%` }} />
            </div>
            <span class="muted">
              {bytes(p.bytes)} of {bytes(p.total)}
              {!j.finished && " · keep this tab open"}
            </span>
          </div>
        );
      })}
    </div>
  );
}

export function save(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

// ---- dialogs ---------------------------------------------------------------------

export interface DialogApi {
  prompt(title: string, label: string, value: string, action: string): Promise<string | undefined>;
  confirm(title: string, text: string, action: string): Promise<boolean>;
  pickFolder(title: string, exclude: string[]): Promise<string | undefined>;
  alert(title: string, text: string): Promise<void>;
}

type Open =
  | { kind: "prompt"; title: string; label: string; value: string; action: string; done: (v?: string) => void }
  | { kind: "confirm"; title: string; text: string; action: string; done: (v: boolean) => void }
  | { kind: "alert"; title: string; text: string; done: () => void }
  | { kind: "folder"; title: string; exclude: string[]; done: (v?: string) => void };

function useDialogs() {
  const [open, setOpen] = useState<Open>();
  const api: DialogApi = {
    prompt: (title, label, value, action) => new Promise((r) => setOpen({ kind: "prompt", title, label, value, action, done: r })),
    confirm: (title, text, action) => new Promise((r) => setOpen({ kind: "confirm", title, text, action, done: r })),
    alert: (title, text) => new Promise((r) => setOpen({ kind: "alert", title, text, done: r })),
    pickFolder: (title, exclude) => new Promise((r) => setOpen({ kind: "folder", title, exclude, done: r })),
  };
  const close = () => setOpen(undefined);
  return { api, element: open ? <DialogView open={open} close={close} /> : null };
}

function Modal({ onCancel, children }: { onCancel: () => void; children: ComponentChildren }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    ref.current?.showModal();
  }, []);
  return (
    <dialog
      class="dlg"
      ref={ref}
      onCancel={(e) => {
        e.preventDefault();
        onCancel();
      }}
    >
      {children}
    </dialog>
  );
}

function DialogView({ open, close }: { open: Open; close: () => void }) {
  const [value, setValue] = useState(open.kind === "prompt" ? open.value : "");
  const finish = (f: () => void) => {
    close();
    f();
  };
  switch (open.kind) {
    case "prompt": {
      const cancel = () => finish(() => open.done(undefined));
      return (
        <Modal onCancel={cancel}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              finish(() => open.done(value.trim()));
            }}
          >
            <span class="t">{open.title}</span>
            <div class="field">
              <label for="dlg-in">{open.label}</label>
              <input
                id="dlg-in"
                class="input"
                value={value}
                onInput={(e) => setValue(e.currentTarget.value)}
                ref={(el) => {
                  if (el && document.activeElement !== el) {
                    el.focus();
                    const dot = open.value.lastIndexOf(".");
                    el.setSelectionRange(0, dot > 0 ? dot : open.value.length);
                  }
                }}
                required
              />
            </div>
            <div class="acts">
              <button type="button" class="btn" onClick={cancel}>
                Cancel
              </button>
              <button class="btn primary" disabled={!value.trim()}>
                {open.action}
              </button>
            </div>
          </form>
        </Modal>
      );
    }
    case "confirm": {
      const cancel = () => finish(() => open.done(false));
      return (
        <Modal onCancel={cancel}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              finish(() => open.done(true));
            }}
          >
            <span class="t">{open.title}</span>
            <p class="muted" style={{ margin: 0, lineHeight: 1.55 }}>
              {open.text}
            </p>
            <div class="acts">
              <button type="button" class="btn" onClick={cancel} autofocus>
                Cancel
              </button>
              <button class="btn danger-solid">{open.action}</button>
            </div>
          </form>
        </Modal>
      );
    }
    case "alert":
      return (
        <Modal onCancel={() => finish(open.done)}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              finish(open.done);
            }}
          >
            <span class="t">{open.title}</span>
            <p class="muted" style={{ margin: 0, lineHeight: 1.55 }}>
              {open.text}
            </p>
            <div class="acts">
              <button class="btn primary" autofocus>
                OK
              </button>
            </div>
          </form>
        </Modal>
      );
    case "folder":
      return <FolderPicker open={open} finish={finish} />;
  }
}

function FolderPicker({ open, finish }: { open: Extract<Open, { kind: "folder" }>; finish: (f: () => void) => void }) {
  const { session } = useApp();
  const [at, setAt] = useState("");
  const [chosen, setChosen] = useState("");
  const kids = session.list(at).filter((n) => n.kind === "dir" && !open.exclude.includes(n.id));
  const crumbs = session.crumbs(at);
  const cancel = () => finish(() => open.done(undefined));
  return (
    <Modal onCancel={cancel}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          finish(() => open.done(chosen));
        }}
      >
        <span class="t">{open.title}</span>
        <div class="crumbs">
          <a
            href="#"
            onClick={(e) => {
              e.preventDefault();
              setAt("");
              setChosen("");
            }}
          >
            Shelf
          </a>
          {crumbs.map((c) => (
            <span key={c.id}>
              ›{" "}
              <a
                href="#"
                onClick={(e) => {
                  e.preventDefault();
                  setAt(c.id);
                  setChosen(c.id);
                }}
              >
                {c.name}
              </a>
            </span>
          ))}
        </div>
        <div class="pick">
          {kids.length === 0 && <div class="muted" style={{ padding: 10, fontSize: 13 }}>No folders here.</div>}
          {kids.map((n) => (
            <button
              type="button"
              key={n.id}
              aria-pressed={chosen === n.id}
              onClick={() => setChosen(n.id)}
              onDblClick={() => {
                setAt(n.id);
                setChosen(n.id);
              }}
            >
              {n.name}
            </button>
          ))}
        </div>
        <div class="acts">
          <button type="button" class="btn" onClick={cancel}>
            Cancel
          </button>
          {chosen && chosen !== at && (
            <button
              type="button"
              class="btn"
              onClick={() => {
                setAt(chosen);
              }}
            >
              Open
            </button>
          )}
          <button class="btn primary">Move here</button>
        </div>
      </form>
    </Modal>
  );
}
