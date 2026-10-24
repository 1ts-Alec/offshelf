import { useEffect, useState } from "preact/hooks";
import { Back, Down, Lock } from "../icons";
import { bytes, previewOf, when } from "../lib/format";
import type { NodeView } from "../lib/session";
import { useActions } from "./Files";
import { href, useApp } from "./Shell";

/** Larger files are offered as a download instead of decrypted into memory. */
const MAX_INLINE = 1_500_000_000;
/** Text previews show the start of the file. */
const MAX_TEXT = 2_000_000;

type Shown =
  | { at: "loading"; bytes: number }
  | { at: "url"; url: string }
  | { at: "text"; text: string; cut: boolean }
  | { at: "none" }
  | { at: "error"; message: string };

export function Preview({ id }: { id: string }) {
  const { session, download } = useApp();
  const act = useActions();
  const n: NodeView | null = session.node(id);
  const kind = n ? previewOf(n.name) : "none";
  const [shown, setShown] = useState<Shown>({ at: "loading", bytes: 0 });
  // Re-read when the file itself changes (an edit from another device).
  const version = n ? `${n.id}:${n.size}:${n.mtime_ms}:${n.chunks}` : "";

  useEffect(() => {
    if (!n || n.kind !== "file") return;
    if (kind === "none" || (kind !== "text" && n.size > MAX_INLINE)) {
      setShown({ at: "none" });
      return;
    }
    const abort = new AbortController();
    let url = "";
    setShown({ at: "loading", bytes: 0 });
    (async () => {
      if (kind === "text") {
        const pt = await session.readRange(n.id, 0, MAX_TEXT, abort.signal);
        setShown({ at: "text", text: new TextDecoder().decode(pt), cut: n.size > MAX_TEXT });
        return;
      }
      const blob = await session.readFile(n.id, (b) => setShown({ at: "loading", bytes: b }), abort.signal);
      url = URL.createObjectURL(blob);
      setShown({ at: "url", url });
    })().catch((e) => {
      if ((e as Error).name !== "AbortError") setShown({ at: "error", message: (e as Error).message });
    });
    return () => {
      abort.abort();
      if (url) URL.revokeObjectURL(url);
    };
  }, [version]);

  if (!n || n.kind !== "file") {
    return (
      <div class="center">
        <div class="card">
          <h1>This file is gone</h1>
          <p>It was moved or deleted on another device.</p>
          <a class="btn primary" href="#/">
            Back to the shelf
          </a>
        </div>
      </div>
    );
  }

  const crumbs = session.crumbs(n.parent);
  const folder = crumbs.length ? crumbs[crumbs.length - 1].name : "Shelf";

  return (
    <>
      <header class="pv-head">
        <a class="btn" href={href.dir(n.parent)}>
          <Back />
          {folder}
        </a>
        <h1>{n.name}</h1>
        <button type="button" class="btn primary dl" onClick={() => download(n)}>
          <Down />
          Download
        </button>
      </header>
      <div class="wrap">
        <main class="main">
          <Stage n={n} kind={kind} shown={shown} />
        </main>
        <aside class="aside" aria-label="File details">
          <div class="facts">
            <div>
              <span>Size</span>
              <span>{bytes(n.size)}</span>
            </div>
            <div>
              <span>Modified</span>
              <span>{when(n.mtime_ms)}</span>
            </div>
            <div>
              <span>Folder</span>
              <span>{["Shelf", ...crumbs.map((c) => c.name)].join(" › ")}</span>
            </div>
          </div>
          <div class="note">
            <Lock size={16} />
            <span>Decrypted in this tab. The Pi only ever sees ciphertext.</span>
          </div>
          <div class="row-btns">
            <button type="button" class="btn" onClick={() => act.rename(n)}>
              Rename…
            </button>
            <button type="button" class="btn" onClick={() => act.move(n)}>
              Move…
            </button>
            <button
              type="button"
              class="btn danger"
              onClick={async () => {
                if (await act.remove(n)) location.hash = href.dir(n.parent);
              }}
            >
              Delete…
            </button>
          </div>
        </aside>
      </div>
    </>
  );
}

function Stage({ n, kind, shown }: { n: NodeView; kind: ReturnType<typeof previewOf>; shown: Shown }) {
  if (shown.at === "error") {
    return (
      <div class="stage">
        <span>{shown.message}</span>
      </div>
    );
  }
  if (shown.at === "none") {
    return (
      <div class="stage">
        <span>{kind === "none" ? "No preview for this kind of file." : "Too big to preview here. Download it instead."}</span>
      </div>
    );
  }
  if (shown.at === "loading") {
    const pct = n.size ? (shown.bytes / n.size) * 100 : 0;
    return (
      <div class="stage">
        <div class="loading-box" aria-busy="true">
          <span>Decrypting</span>
          <div class="bar">
            <span style={{ width: `${pct}%` }} />
          </div>
          <span>
            {bytes(shown.bytes)} of {bytes(n.size)}
          </span>
        </div>
      </div>
    );
  }
  if (shown.at === "text") {
    return (
      <pre class="textview">
        {shown.text}
        {shown.cut && "\n…"}
      </pre>
    );
  }
  switch (kind) {
    case "image":
      return (
        <div class="stage">
          <img src={shown.url} alt={n.name} />
        </div>
      );
    case "video":
      return (
        <div class="stage video">
          <video src={shown.url} controls autoplay playsInline />
        </div>
      );
    case "audio":
      return (
        <div class="stage">
          <audio src={shown.url} controls autoplay style={{ width: "100%", maxWidth: 520 }} />
        </div>
      );
    case "pdf":
      return (
        <div class="stage pdf">
          <iframe src={shown.url} title={n.name} />
        </div>
      );
    default:
      return null;
  }
}
