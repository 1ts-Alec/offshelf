import { render } from "preact";
import init from "./wasm/oshelf_web.js";
import { App } from "./app";
import "./styles.css";

await init();
render(<App />, document.getElementById("app")!);
