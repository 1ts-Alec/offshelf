export type Preview = "image" | "video" | "audio" | "pdf" | "text" | "none";

const EXT: Record<string, [Preview, string]> = {
  jpg: ["image", "image/jpeg"],
  jpeg: ["image", "image/jpeg"],
  png: ["image", "image/png"],
  gif: ["image", "image/gif"],
  webp: ["image", "image/webp"],
  avif: ["image", "image/avif"],
  heic: ["image", "image/heic"],
  heif: ["image", "image/heif"],
  bmp: ["image", "image/bmp"],
  svg: ["image", "image/svg+xml"],
  mp4: ["video", "video/mp4"],
  m4v: ["video", "video/mp4"],
  mov: ["video", "video/quicktime"],
  webm: ["video", "video/webm"],
  mkv: ["video", "video/x-matroska"],
  mp3: ["audio", "audio/mpeg"],
  m4a: ["audio", "audio/mp4"],
  aac: ["audio", "audio/aac"],
  wav: ["audio", "audio/wav"],
  flac: ["audio", "audio/flac"],
  ogg: ["audio", "audio/ogg"],
  opus: ["audio", "audio/ogg"],
  pdf: ["pdf", "application/pdf"],
};

const TEXT = new Set(
  "txt md markdown json csv tsv log yaml yml toml ini conf cfg xml html htm css js mjs ts tsx jsx rs py rb go swift kt java c h cpp hpp sh zsh fish sql env gitignore srt vtt tex".split(
    " ",
  ),
);

function ext(name: string): string {
  const i = name.lastIndexOf(".");
  return i > 0 ? name.slice(i + 1).toLowerCase() : "";
}

export function previewOf(name: string): Preview {
  const e = ext(name);
  if (EXT[e]) return EXT[e][0];
  if (TEXT.has(e)) return "text";
  return "none";
}

export function mimeOf(name: string): string {
  const e = ext(name);
  if (EXT[e]) return EXT[e][1];
  if (TEXT.has(e)) return "text/plain";
  return "application/octet-stream";
}

export function bytes(n: number): string {
  if (n < 1000) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let v = n;
  let u = -1;
  do {
    v /= 1000;
    u++;
  } while (v >= 1000 && u < units.length - 1);
  return `${v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)} ${units[u]}`;
}

const DAY = 86_400_000;

export function when(ms: number): string {
  if (!ms) return "";
  const d = new Date(ms);
  const now = new Date();
  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const time = d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  if (ms >= startOfToday) return `Today ${time}`;
  if (ms >= startOfToday - DAY) return "Yesterday";
  const sameYear = d.getFullYear() === now.getFullYear();
  return d.toLocaleDateString(undefined, sameYear ? { day: "numeric", month: "short" } : { day: "numeric", month: "short", year: "numeric" });
}

export function clock(ms: number): string {
  return new Date(ms).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

/** "Safari on Mac" and the like, as a default device name. */
export function browserName(): string {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /Firefox\//.test(ua)
      ? "Firefox"
      : /Chrome\//.test(ua)
        ? "Chrome"
        : /Safari\//.test(ua)
          ? "Safari"
          : "Browser";
  const os = /iPhone|iPad/.test(ua)
    ? "iPhone"
    : /Mac OS X/.test(ua)
      ? "Mac"
      : /Android/.test(ua)
        ? "Android"
        : /Windows/.test(ua)
          ? "Windows"
          : /Linux/.test(ua)
            ? "Linux"
            : "";
  return os ? `${browser} on ${os}` : browser;
}
