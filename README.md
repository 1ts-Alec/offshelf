# Offshelf

Self hosted, end to end encrypted file shelf. Files live on a Raspberry Pi
with an SSD, show up in Finder like they're still on your Mac, and stream
only the bytes an app asks for. The Pi only ever sees ciphertext.

Status: early. This repo holds the crypto spec and the server core.

## Layout

| Path | What |
| --- | --- |
| `spec/crypto.md` | Chunk format, key hierarchy, encrypted manifest |
| `crates/oshelf-core` | Chunk sealing, chunk ids, byte range mapping (shared with the Mac and web apps) |
| `crates/oshelfd` | The server: axum API, content addressed chunk store, SQLite metadata |

## Run the server

```sh
cargo build --release
./target/release/oshelfd --data-dir /mnt/shelf serve --bind 192.168.1.20:8740
```

oshelfd refuses to bind a public address. For access away from home, put
your own tunnel (for example Cloudflare Tunnel) in front of it.

Device pairing and signed requests aren't built yet, so for now only run
oshelfd on a network you trust.

## API v1

| Method and path | Does |
| --- | --- |
| `PUT /v1/chunks/{id}` | Upload one sealed chunk; `id` must be BLAKE3 of the body |
| `GET /v1/chunks/{id}` | Download one sealed chunk |
| `POST /v1/objects` | Register a file version: `{ "id", "chunks": [...] }` |
| `GET /v1/objects/{id}/chunks?first=&last=` | Ranged read: framed stream of chunks `first..=last` |
| `DELETE /v1/objects/{id}` | Drop a file version (chunks go at the next `gc`) |
| `GET /v1/manifest/head` | Head revision and hash |
| `GET /v1/manifest/log?since=` | Sealed log entries after a revision |
| `POST /v1/manifest/log` | Append a sealed entry, `If-Match: <head revision>` |
| `GET` / `PUT /v1/vault` | Wrapped master key header |
| `GET /v1/events` | Server-sent events, one per new revision |
| `GET /v1/usage` | Chunk count, stored bytes, objects, revision |

## License

Apache License 2.0. If you use or modify Offshelf, keep the `NOTICE` file
and mark the files you changed.
