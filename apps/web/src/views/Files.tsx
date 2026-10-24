import { useEffect, useRef, useState } from "preact/hooks";
import { AudioIcon, DocIcon, Folder, ImageIcon, More, Shelf, Up, VideoIcon } from "../icons";
import { json } from "../lib/api";
import { bytes, previewOf, when } from "../lib/format";
import type { NodeView } from "../lib/session";
import { href, useApp } from "./Shell";

export function KindIcon({ n, size = 18 }: { n: NodeView; size?: number }) {
  if (n.kind === "dir") return <Folder size={size} />;
  switch (previewOf(n.name)) {
    case "image":
      return <ImageIcon size={size} />;
    case "video":
      return <VideoIcon size={size} />;
    case "audio":
      return <AudioIcon size={size} />;
    default:
      return <DocIcon size={size} />;
  }
}

interface Usage {
  stored_bytes?: number;
  disk_free?: number;
  disk_total?: number;
}

function useUsage(): Usage | undefined {
  const { session } = useApp();
  const [u, setU] = useState<Usage>();
  useEffect(() => {
    let live = true;
    const load = () =>
      session.api
        .call("GET", "/v1/usage")
        .then((r) => live && setU(json(r)))
        .catch(() => undefined);
    load();
    const t = setInterval(load, 60_000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [session]);
  return u;
}

function Sidebar({ dir }: { dir: string }) {
  const { session } = useApp();
  const usage = useUsage();
  const top = session.list("").filter((n) => n.kind === "dir");
  const trail = new Set(session.crumbs(dir).map((c) => c.id));
  const used = usage?.disk_total ? usage.disk_total - (usage.disk_free ?? 0) : undefined;
  return (
    <nav aria-label="Folders" class="side">
      <a class="tree" href="#/" aria-current={dir === "" ? "page" : undefined}>
        <Shelf />
        Shelf
      </a>
      {top.map((n) => (
        <a class="tree sub" href={href.dir(n.id)} key={n.id} aria-current={trail.has(n.id) ? "page" : undefined}>
          <Folder size={16} />
          {n.name}
        </a>
      ))}
      {used !== undefined && usage?.disk_total ? (
        <div class="usage-box">
          {bytes(used)} of {bytes(usage.disk_total)} used
          <div class="bar">
            <span style={{ width: `${(used / usage.disk_total) * 100}%` }} />
          </div>
        </div>
      ) : null}
    </nav>
  );
}

export function useActions() {
  const { session, dialog, download } = useApp();
  const guard = async (f: () => Promise<unknown>) => {
    try {
      await f();
    } catch (e) {
      await dialog.alert("That didn't work", (e as Error).message);
    }
  };
  return {
    download,
    async rename(n: NodeView) {
      const name = await dialog.prompt("Rename", "Name", n.name, "Rename");
      if (name && name !== n.name) await guard(() => session.rename(n.id, name));
    },
    async move(n: NodeView) {
      const dest = await dialog.pickFolder(`Move ${n.name}`, [n.id]);
      if (dest !== undefined) await guard(() => session.move(n.id, dest, n.name));
    },
    async remove(n: NodeView): Promise<boolean> {
      const what = n.kind === "dir" ? `${n.name} and everything in it` : n.name;
      const ok = await dialog.confirm(`Delete ${n.name}?`, `This removes ${what} from every device.`, "Delete");
      if (!ok) return false;
      let done = false;
      await guard(async () => {
        await session.remove([n.id]);
        done = true;
      });
      return done;
    },
  };
}

/** Opens below the button, or above it near the bottom of the window. The
 * menu is fixed so the table's scroll box can't clip it. */
function RowMenu({ n }: { n: NodeView }) {
  const [open, setOpen] = useState(false);
  const [at, setAt] = useState<{ top?: number; bottom?: number; right: number }>({ right: 0 });
  const ref = useRef<HTMLDivElement>(null);
  const act = useActions();
  useEffect(() => {
    if (!open) return;
    const away = (e: Event) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    const close = () => setOpen(false);
    document.addEventListener("pointerdown", away);
    document.addEventListener("keydown", esc);
    addEventListener("scroll", close, true);
    addEventListener("resize", close);
    ref.current?.querySelector<HTMLElement>(".mi")?.focus();
    return () => {
      document.removeEventListener("pointerdown", away);
      document.removeEventListener("keydown", esc);
      removeEventListener("scroll", close, true);
      removeEventListener("resize", close);
    };
  }, [open]);
  const run = (f: () => void) => () => {
    setOpen(false);
    f();
  };
  const isFile = n.kind === "file";
  return (
    <div ref={ref}>
      <button
        type="button"
        class="icon-btn"
        aria-label={`More actions for ${n.name}`}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          const right = innerWidth - r.right;
          setAt(innerHeight - r.bottom < 240 ? { bottom: innerHeight - r.top + 4, right } : { top: r.bottom + 4, right });
          setOpen(!open);
        }}
      >
        <More />
      </button>
      {open && (
        <div class="menu" role="menu" aria-label="Actions" style={at}>
          {isFile ? (
            <a class="mi" role="menuitem" href={href.preview(n.id)}>
              Preview
            </a>
          ) : (
            <a class="mi" role="menuitem" href={href.dir(n.id)}>
              Open
            </a>
          )}
          {isFile && (
            <button type="button" class="mi" role="menuitem" onClick={run(() => act.download(n))}>
              Download
            </button>
          )}
          <button type="button" class="mi" role="menuitem" onClick={run(() => act.rename(n))}>
            Rename…
          </button>
          <button type="button" class="mi" role="menuitem" onClick={run(() => act.move(n))}>
            Move to…
          </button>
          <hr />
          <button type="button" class="mi danger" role="menuitem" onClick={run(() => act.remove(n))}>
            Delete…
          </button>
        </div>
      )}
    </div>
  );
}

function Table({ rows, showFolder }: { rows: NodeView[]; showFolder?: boolean }) {
  const { session } = useApp();
  return (
    <table class="files">
      <thead>
        <tr>
          <th style={{ width: "52%" }}>Name</th>
          <th>Size</th>
          <th>{showFolder ? "Folder" : "Modified"}</th>
          <th>
            <span class="visually-hidden">Actions</span>
          </th>
        </tr>
      </thead>
      <tbody>
        {rows.map((n) => (
          <tr key={n.id}>
            <td>
              <a class="name" href={n.kind === "dir" ? href.dir(n.id) : href.preview(n.id)}>
                <span style={{ color: n.kind === "dir" ? "var(--accent)" : "var(--secondary)", display: "inline-flex" }}>
                  <KindIcon n={n} />
                </span>
                {n.name}
              </a>
            </td>
            <td class="meta">{bytes(n.total)}</td>
            <td class="meta">
              {showFolder
                ? session
                    .crumbs(n.parent)
                    .map((c) => c.name)
                    .join(" › ") || "Shelf"
                : when(n.mtime_ms)}
            </td>
            <td class="act">
              <RowMenu n={n} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function Files({ dir, query, clearQuery }: { dir: string; query: string; clearQuery: () => void }) {
  const { session, upload, dialog } = useApp();
  const input = useRef<HTMLInputElement>(null);
  const [drag, setDrag] = useState(false);
  const exists = dir === "" || session.shelf.is_dir(dir);

  useEffect(() => {
    if (query) clearQuery();
  }, [dir]);

  if (!exists) {
    return (
      <div class="wrap">
        <Sidebar dir="" />
        <main class="main">
          <div class="panel empty">
            <span class="t">This folder is gone</span>
            <span class="muted">It was moved or deleted on another device.</span>
            <a class="btn primary" href="#/">
              Back to the shelf
            </a>
          </div>
        </main>
      </div>
    );
  }

  const searching = query.trim().length > 0;
  const rows: NodeView[] = searching ? session.shelf.search(query, 200) : session.list(dir);
  const crumbs = session.crumbs(dir);
  const title = searching ? "Search" : crumbs.length ? crumbs[crumbs.length - 1].name : "Shelf";

  async function newFolder() {
    const name = await dialog.prompt("New folder", "Name", "", "Create");
    if (!name) return;
    try {
      const id = (await session.mkdir(dir, name)) ?? session.list(dir).find((n) => n.kind === "dir" && n.name === name.normalize("NFC"))?.id;
      if (id) location.hash = href.dir(id);
    } catch (e) {
      await dialog.alert("That didn't work", (e as Error).message);
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDrag(false);
    const files = Array.from(e.dataTransfer?.files ?? []).filter((f) => f.size > 0 || f.type !== "");
    upload(dir, files);
  }

  return (
    <div class="wrap">
      <Sidebar dir={dir} />
      <main class="main">
        <div class="head-row">
          <div style={{ display: "flex", flexDirection: "column", gap: 4, minWidth: 0 }}>
            {!searching && crumbs.length > 0 && (
              <nav class="crumbs" aria-label="Path">
                <a href="#/">Shelf</a>
                {crumbs.slice(0, -1).map((c) => (
                  <span key={c.id}>
                    › <a href={href.dir(c.id)}>{c.name}</a>
                  </span>
                ))}
                <span>› {title}</span>
              </nav>
            )}
            <h1 style={{ overflowWrap: "anywhere" }}>{title}</h1>
          </div>
          {!searching && (
            <div class="actions">
              <button type="button" class="btn" onClick={newFolder}>
                <Folder size={14} />
                New folder
              </button>
              <button type="button" class="btn primary" onClick={() => input.current?.click()}>
                <Up />
                Upload
              </button>
              <input
                ref={input}
                type="file"
                multiple
                hidden
                onChange={(e) => {
                  upload(dir, Array.from(e.currentTarget.files ?? []));
                  e.currentTarget.value = "";
                }}
              />
            </div>
          )}
        </div>

        <div
          class={`panel${drag ? " drop" : ""}`}
          onDragOver={(e) => {
            if (searching) return;
            e.preventDefault();
            setDrag(true);
          }}
          onDragLeave={() => setDrag(false)}
          onDrop={searching ? undefined : onDrop}
        >
          {rows.length === 0 ? (
            searching ? (
              <div class="empty">
                <span class="t">No matches</span>
                <span class="muted">Nothing on the shelf is called that.</span>
              </div>
            ) : (
              <div class="empty">
                <span class="big-icon">
                  <Folder size={24} />
                </span>
                <span class="t">This folder is empty</span>
                <span class="muted">Drop files here to upload.</span>
                <button type="button" class="btn primary" onClick={() => input.current?.click()}>
                  Upload files
                </button>
              </div>
            )
          ) : (
            <Table rows={rows} showFolder={searching} />
          )}
        </div>
      </main>
    </div>
  );
}
