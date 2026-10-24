// Stroke icons from the mockups, drawn in currentColor.

type P = { size?: number };

export const Mark = ({ size = 28 }: P) => (
  <span class="mark" style={{ width: size, height: size }} aria-hidden="true">
    <svg width={size} height={size} viewBox="0 0 100 100" fill="none">
      <rect x="26" y="22" width="48" height="12" rx="4" stroke="currentColor" stroke-width="6" />
      <rect x="24" y="48" width="52" height="12" rx="4" fill="currentColor" />
      <rect x="24" y="65" width="52" height="12" rx="4" fill="currentColor" />
    </svg>
  </span>
);

export const Folder = ({ size = 18 }: P) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <path
      d="M2 4.5c0-.6.4-1 1-1h3.2l1.3 1.5H13c.6 0 1 .4 1 1v6c0 .6-.4 1-1 1H3c-.6 0-1-.4-1-1z"
      stroke="currentColor"
      stroke-width="1.3"
    />
  </svg>
);

export const Shelf = ({ size = 16 }: P) => (
  <svg width={size} height={size} viewBox="0 0 18 16" fill="none" aria-hidden="true">
    <path d="M2 4h14M2 8h14M5 12h8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
  </svg>
);

export const VideoIcon = ({ size = 18 }: P) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <rect x="2" y="3.5" width="12" height="9" rx="1.5" stroke="currentColor" stroke-width="1.3" />
    <path d="M6.8 6.2v3.6L9.8 8z" fill="currentColor" />
  </svg>
);

export const ImageIcon = ({ size = 18 }: P) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <rect x="2.5" y="3" width="11" height="10" rx="1.5" stroke="currentColor" stroke-width="1.3" />
    <circle cx="6" cy="6.5" r="1.2" stroke="currentColor" stroke-width="1.1" />
    <path d="M3 11.5l3.3-3 2.4 2 2-1.6 2.8 2.4" stroke="currentColor" stroke-width="1.1" stroke-linejoin="round" />
  </svg>
);

export const DocIcon = ({ size = 18 }: P) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <path d="M4 2.5h5.5L12 5v8.5H4z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round" />
    <path d="M6 8.5h4M6 10.5h3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" />
  </svg>
);

export const AudioIcon = ({ size = 18 }: P) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <path d="M4 2.5h5.5L12 5v8.5H4z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round" />
    <path d="M7 7.5v3.2M7 7.5l2.5-.6v3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" />
  </svg>
);

export const Search = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <circle cx="7" cy="7" r="4.5" stroke="currentColor" stroke-width="1.4" />
    <path d="M10.5 10.5L14 14" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
  </svg>
);

export const Lock = ({ size = 14 }: P) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <rect x="3" y="7" width="10" height="7" rx="1.5" stroke="currentColor" stroke-width="1.3" />
    <path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" stroke="currentColor" stroke-width="1.3" />
  </svg>
);

export const More = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
    <circle cx="3.5" cy="8" r="1.3" />
    <circle cx="8" cy="8" r="1.3" />
    <circle cx="12.5" cy="8" r="1.3" />
  </svg>
);

export const Up = ({ size = 14 }: P) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <path d="M8 12.5V4M4.5 7.5L8 4l3.5 3.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" />
  </svg>
);

export const Down = ({ size = 14 }: P) => (
  <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <path d="M8 3.5V12M4.5 8.5L8 12l3.5-3.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" />
  </svg>
);

export const Back = () => (
  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <path d="M10 3.5L5.5 8l4.5 4.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
  </svg>
);

export const Alert = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true" style={{ flex: "none" }}>
    <circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.4" />
    <path d="M8 5v3.5M8 10.8v.1" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
  </svg>
);

export const Warn = () => (
  <svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <path d="M8 2.5l6 10.5H2z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" />
  </svg>
);

export const NoWifi = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true" style={{ flex: "none" }}>
    <path
      d="M2 6.5a9 9 0 0 1 12 0M4.2 9a5.6 5.6 0 0 1 7.6 0M6.5 11.4a2.2 2.2 0 0 1 3 0M2.5 13.5l11-11"
      stroke="currentColor"
      stroke-width="1.4"
      stroke-linecap="round"
    />
  </svg>
);

export const Healthy = () => (
  <svg width="22" height="22" viewBox="0 0 16 16" fill="none" aria-hidden="true">
    <circle cx="8" cy="8" r="6" fill="var(--accent)" />
    <path d="M5.3 8.2l1.8 1.7 3.6-3.8" stroke="var(--on-accent)" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" />
  </svg>
);
