# Offshelf

Self hosted, end to end encrypted file shelf. Files live on a Raspberry Pi
with an SSD, show up in Finder like they're still on your Mac, and stream
only the bytes an app asks for. The Pi only ever sees ciphertext.

Status: early. This repo holds the crypto spec and the server core.

## Layout

| Path | What |
| --- | --- |
| `spec/crypto.md` | Chunk format, key hierarchy, encrypted manifest |
| `spec/vectors/` | Test vectors every implementation must pass |
| `fuzz/` | cargo-fuzz targets, run nightly |
| `crates/oshelf-core` | Chunk sealing, chunk ids, byte range mapping (shared with the Mac and web apps) |
| `crates/oshelf` | The `oshelf` command line client |
| `crates/oshelf-mac` | The Mac app's engine: loopback NFS mount, range reads, chunk cache, pins, offload, uploads, host switching |
| `assets/brand/` | App icon, menu bar glyph and favicon |
| `crates/oshelfd` | The server: axum API, content addressed chunk store, SQLite metadata |

## Run the server

```sh
cargo build --release
./target/release/oshelfd --data-dir /mnt/shelf serve --bind 192.168.1.20:8740
```

oshelfd refuses to bind a public address. For access away from home, put
your own tunnel (for example Cloudflare Tunnel) in front of it.

Every request except `/v1/health` and `/v1/pair` must be signed by a paired
device. The Pi signs its buffered responses in turn (`X-Oshelf-Sig`). To pair the first device, run this on the Pi and enter the code on
the device within 10 minutes:

```sh
oshelfd --data-dir /mnt/shelf pair      # prints a code like 7KQ2-M9XD
oshelfd --data-dir /mnt/shelf devices   # list paired devices
oshelfd --data-dir /mnt/shelf revoke <device id>
```

## Use the CLI

```sh
cargo build --release -p oshelf
oshelf pair http://192.168.1.20:8740 7KQ2-M9XD --name "MacBook"
oshelf init                      # set a passphrase, write down the 24 recovery words
oshelf put ~/Pictures/Trips --to Photos
oshelf ls Photos/Trips
oshelf get Photos/Trips/rome.jpg ~/Desktop
oshelf mv Photos/Trips Archive
oshelf rm Archive/old.mov
oshelf export /Volumes/Backup/shelf   # decrypted copy of everything
oshelf status
```

Other commands: `cat`, `mkdir`, `usage`, `devices`, `pair-code` (to add
another device), `revoke`, `passwd`, `compact`. Commands that read the shelf
ask for the passphrase, or take it from `OSHELF_PASSPHRASE`; add `--recovery`
to unlock with the recovery words. Device state lives in `~/.config/oshelf`
(or `OSHELF_HOME`).

## Mount it on a Mac (development)

The Mac app embeds `crates/oshelf-mac`. Until the app ships, the same engine
runs from the command line, using the device the CLI paired:

```sh
cargo build --release -p oshelf-mac
./target/release/oshelf-mount --at ~/OffshelfMount
```

It serves the shelf on a loopback NFS port and mounts it with the system's
`mount_nfs` (no admin rights, no kernel extension). Reads fetch only the 1 MiB
chunks they touch, plus a readahead that grows with sequential reading.
Writes land in a local staging file and upload in the background once quiet;
`.DS_Store` and `._*` files stay on the Mac.

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
| `PUT /v1/manifest/snapshots/{rev}?object=` | Store a sealed snapshot header; segments live in `object` |
| `GET /v1/manifest/snapshot` | Latest snapshot header (revision and object in headers) |
| `GET` / `PUT /v1/vault` | Wrapped master key header |
| `GET /v1/events` | Server-sent events, one per new revision |
| `GET /v1/usage` | Chunk count, stored bytes, objects, revision |
| `POST /v1/pair` | Pair a device with a code (unsigned) |
| `POST /v1/pairing-codes` | Make a pairing code from a paired device |
| `GET /v1/devices` | List paired devices |
| `DELETE /v1/devices/{id}` | Revoke a device |

## License

Apache License 2.0. If you use or modify Offshelf, keep the `NOTICE` file
and mark the files you changed.
