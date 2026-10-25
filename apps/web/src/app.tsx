import { useEffect, useState } from "preact/hooks";
import { ApiError, Offline, type Api } from "./lib/api";
import { apiFor, pair } from "./lib/device";
import { runKdf } from "./lib/kdf";
import { Session, TamperError } from "./lib/session";
import * as store from "./lib/store";
import { Loading, NewPassphrase, Pair, Problem, Unlock } from "./views/Gate";
import { Shell } from "./views/Shell";
import { ChooseDrive, CreateShelf, loadStorage, type StorageInfo } from "./views/Setup";

const STAY_MS = 7 * 86_400_000;
/** The master key for this tab only, sealed under the local wrap key. */
const TAB_KEY = "offshelf-mk";

type State =
  | { at: "boot" }
  | { at: "pair" }
  | { at: "drive"; info: StorageInfo }
  | { at: "novault" }
  | { at: "unlock" }
  | { at: "loading"; loaded: number; total: number }
  | { at: "newpass"; mk: Uint8Array }
  | { at: "open"; session: Session }
  | { at: "problem"; title: string; text: string; repair?: boolean };

const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function App() {
  const [state, setState] = useState<State>({ at: "boot" });
  const [device, setDevice] = useState<store.Device>();
  const [api, setApi] = useState<Api>();
  const [vault, setVault] = useState<{ bytes: Uint8Array; etag: string }>();

  async function fail(e: unknown) {
    if (e instanceof TamperError) {
      setState({ at: "problem", title: "Stopped to be safe", text: e.message });
    } else if (e instanceof Offline) {
      setState({ at: "problem", title: "Can't reach your shelf", text: "Check that the Pi is on and this device is on the same network." });
    } else if (e instanceof ApiError && e.status === 401) {
      setState({ at: "problem", title: "This browser isn't paired", text: "It may have been revoked. Pair it again.", repair: true });
    } else {
      setState({ at: "problem", title: "Something went wrong", text: (e as Error).message });
    }
  }

  async function boot() {
    try {
      const d = await store.loadDevice();
      if (!d) return setState({ at: "pair" });
      setDevice(d);
      const a = await apiFor(d);
      setApi(a);
      // First run: pick the drive before anything is stored.
      const info = await loadStorage(a);
      if (!info.configured) return setState({ at: "drive", info });
      const r = await a.call("GET", "/v1/vault", { allow: [404] });
      if (r.status === 404) return setState({ at: "novault" });
      const v = { bytes: r.body, etag: (r.headers.get("etag") ?? "").replaceAll('"', "") };
      setVault(v);
      const mk = await rememberedKey();
      if (mk) return await open(a, d, v.bytes, mk);
      setState({ at: "unlock" });
    } catch (e) {
      fail(e);
    }
  }

  async function rememberedKey(): Promise<Uint8Array | undefined> {
    try {
      const tab = sessionStorage.getItem(TAB_KEY);
      if (tab) return await store.unseal("tab-mk", unb64(tab));
      const stay = await store.loadStay();
      if (stay && stay.expires > Date.now()) return await store.unseal("stay-mk", stay.mk);
      if (stay) await store.forgetStay();
    } catch (e) {
      console.warn("remembered key unusable", e);
    }
    return undefined;
  }

  async function open(a: Api, d: store.Device, v: Uint8Array, mk: Uint8Array) {
    setState({ at: "loading", loaded: 0, total: 0 });
    const session = await Session.open(a, d, mk, v, (loaded, total) => setState({ at: "loading", loaded, total }));
    sessionStorage.setItem(TAB_KEY, b64(await store.seal("tab-mk", mk)));
    session.start(fail);
    setState({ at: "open", session });
  }

  useEffect(() => {
    boot();
  }, []);

  async function onPair(code: string, name: string) {
    await pair(code, name);
    await boot();
  }

  async function onUnlock(secret: string, recovery: boolean, stay: boolean) {
    const mk = await runKdf(
      recovery ? { op: "recovery", vault: vault!.bytes, words: secret } : { op: "passphrase", vault: vault!.bytes, passphrase: secret },
    );
    if (stay) {
      await store.saveStay({ mk: await store.seal("stay-mk", mk), expires: Date.now() + STAY_MS });
    } else {
      await store.forgetStay();
    }
    if (recovery) return setState({ at: "newpass", mk });
    try {
      await open(api!, device!, vault!.bytes, mk);
    } catch (e) {
      fail(e);
    }
  }

  async function onNewPassphrase(mk: Uint8Array, passphrase: string) {
    const next = await runKdf({ op: "rewrap", vault: vault!.bytes, mk, passphrase });
    await api!.call("PUT", "/v1/vault", { body: next, headers: { "if-match": vault!.etag } });
    setVault({ bytes: next, etag: "" });
    try {
      await open(api!, device!, next, mk);
    } catch (e) {
      fail(e);
    }
  }

  async function lock() {
    if (state.at === "open") state.session.stop();
    sessionStorage.removeItem(TAB_KEY);
    await store.forgetStay();
    setState({ at: "unlock" });
  }

  async function unpair() {
    if (state.at === "open") state.session.stop();
    sessionStorage.removeItem(TAB_KEY);
    await store.clearAll();
    setDevice(undefined);
    setState({ at: "pair" });
  }

  switch (state.at) {
    case "boot":
      return null;
    case "pair":
      return <Pair onPair={onPair} />;
    case "drive":
      return <ChooseDrive api={api!} info={state.info} onDone={boot} />;
    case "novault":
      return (
        <CreateShelf
          api={api!}
          onDone={async (v) => {
            const r = await api!.call("GET", "/v1/vault");
            setVault({ bytes: r.body, etag: (r.headers.get("etag") ?? "").replaceAll('"', "") });
            await open(api!, device!, r.body, v.mk);
          }}
        />
      );
    case "unlock":
      return <Unlock deviceName={device?.name ?? ""} onUnlock={onUnlock} onForget={unpair} />;
    case "newpass":
      return <NewPassphrase onSave={(p) => onNewPassphrase(state.mk, p)} />;
    case "loading":
      return <Loading loaded={state.loaded} total={state.total} />;
    case "problem":
      return (
        <Problem
          title={state.title}
          text={state.text}
          action={
            <div class="row-btns">
              <button class="btn primary" onClick={() => (state.repair ? unpair() : location.reload())}>
                {state.repair ? "Pair again" : "Try again"}
              </button>
            </div>
          }
        />
      );
    case "open":
      return <Shell session={state.session} onLock={lock} />;
  }
}
