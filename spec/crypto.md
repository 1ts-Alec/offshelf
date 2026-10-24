# Offshelf crypto spec v1

Status: accepted 2026-10-24. Review copy: https://claude.ai/artifact/XBSDGmm3zHzWcV4hbpSKWz

## Threat model

The Pi stores and serves ciphertext and never holds a key that can decrypt file
contents, names, or the tree. Everything that needs a key happens on the Mac
app or in the browser.

| | Server (oshelfd) sees | Server never sees |
| --- | --- | --- |
| Files | Number of files, ciphertext size of each, chunk count, upload and read times | Contents, names, paths, folder structure, plaintext mtimes |
| Tree | Manifest revision number, sealed blob sizes, which device wrote each change | Any entry inside the manifest |
| Keys | Wrapped master key (passphrase slot + recovery slot), device public keys | Passphrase, master key, recovery key, file keys |

In scope: a curious or compromised Pi, a stolen SSD, an attacker on the LAN or
in front of the Cloudflare tunnel. The server cannot read data, cannot swap,
reorder, or roll back chunks or manifest entries without a client detecting
it, and cannot brute force the passphrase unless it is itself compromised (the
vault header is only served to paired devices).

Out of scope for v1: a compromised Mac, hiding file sizes (no padding beyond
the 1 MiB chunk grid), hiding access patterns, and a server that freezes the
tree by withholding new revisions from a device that never talks to another
device. A destructive server can always delete data; backups are the defense.

## Primitives and encodings

All primitives come from RustCrypto crates in the shared Rust core, used by the
Mac app via UniFFI and by the web app compiled to WebAssembly (WebCrypto has
no XChaCha20, Argon2id, or BLAKE3; it is used only for randomness and the
non-extractable device key).

| Job | Primitive | Parameters |
| --- | --- | --- |
| Sealing chunks, manifest, wrapped keys | XChaCha20-Poly1305 | 32 byte key, 24 byte nonce, 16 byte tag |
| Passphrase to key | Argon2id | m = 256 MiB, t = 3, p = 1, 16 byte salt (stored, can be raised later) |
| Deriving subkeys | HKDF-SHA256 | salt = vault id, info = fixed label per key |
| Content address, log chain | BLAKE3-256 | 32 byte output |
| Device identity | Ed25519 | one keypair per device |
| Randomness | OS CSPRNG | getrandom on Mac and Linux, crypto.getRandomValues in the browser |

Integers are little endian. Ids are 16 random bytes, chunk ids 32 bytes, both
lowercase hex in URLs. Structured data (manifest entries, log entries, vault
header) is deterministic CBOR (RFC 8949 core deterministic encoding),
compressed with zstd before sealing where noted. Every sealed object starts
with a 4 byte magic and a format version.

## Key hierarchy

One random 32 byte master key (MK) is created at `oshelf init` on the first Mac
and never changes. The passphrase and the recovery key each only unwrap MK, so
changing the passphrase is a re-wrap, not a re-encrypt.

| Key | Made how | Stored where | Used for |
| --- | --- | --- | --- |
| Passphrase key (PK) | Argon2id(passphrase, salt) | Never stored | Unwraps MK from the passphrase slot |
| Recovery key (RK) | 32 random bytes, shown once as 24 words (BIP39) | On paper with the user | Unwraps MK from the recovery slot |
| Master key (MK) | 32 random bytes at init | Wrapped twice in the vault header on the Pi; plaintext in the macOS Keychain | Root of everything below |
| Manifest key (KM) | HKDF(MK, "offshelf/v1/manifest") | Derived on unlock | Seals log entries |
| File key (FK) | 32 random bytes per file | Inside the file's manifest entry | Seals that file's chunks |
| Device key | Ed25519 keypair per device | Mac Keychain, or non-extractable in browser IndexedDB; Pi keeps the public half | Signs API requests |

```
VaultHeader (CBOR, magic "OSVH", version 1)
  vault_id    16 bytes
  kdf         { alg: "argon2id", m_kib: 262144, t: 3, p: 1, salt: 16 bytes }
  slots       [ { kind: "passphrase" | "recovery", nonce: 24 bytes, sealed_mk: 48 bytes } ]

sealed_mk = XChaCha20-Poly1305(key = PK or RK, nonce = random,
            aad = "offshelf/v1/vault" || vault_id || kind)
```

A wrong passphrase shows up as a failed tag check; there is no separate
verifier. FK is random per file so a future share-one-folder feature only has
to hand out file keys.

## Chunk format

Files are cut into 1 MiB plaintext chunks (the last one shorter; an empty file
has none). Each chunk is sealed on its own with a random nonce stored in its
header. Overhead is 48 bytes per chunk.

```
stored chunk = header (32 bytes) || ciphertext (pt_len bytes) || tag (16 bytes)

header
  0..4    magic      "OSC1"
  4       version    0x01
  5       alg        0x01 = XChaCha20-Poly1305
  6..8    reserved   0x0000 (must be zero)
  8..32   nonce      24 random bytes

aad = header[0..8] || file_id (16) || u64le(chunk_index)
key = FK of the file
```

The nonce is random rather than derived from file id + chunk index: editing a
file puts new plaintext at the same index under the same key, and a derived
nonce would repeat, which breaks XChaCha20-Poly1305 completely. A 24 byte
random nonce makes collisions negligible, and an edit only reseals the chunks
that changed.

The AAD pins each chunk to one file and one position. Swapping in an older
version of the same chunk is caught by the chunk id check below.

Reference implementation: `crates/oshelf-core/src/chunk.rs`.

### Range reads

```
first = floor(start / 2^20)
last  = floor((end - 1) / 2^20)
skip  = start mod 2^20
```

The client fetches chunks first..last from the file's chunk map, checks and
opens each, drops `skip` bytes from the first and trims to the range length.
Chunk size is recorded per file in the manifest so it can change later.
Reference implementation: `crates/oshelf-core/src/range.rs`.

## Content addressing and garbage collection

A chunk's id is BLAKE3-256 of its stored bytes. The Pi checks the hash on
upload and stores the chunk at `chunks/ab/cd/<id>`. The client checks it again
on every read, against the id in the manifest, so every chunk is tamper
evident and rollback proof.

No cross-file dedup in v1: random nonces mean equal plaintext never gives equal
ciphertext. Copies made inside Offshelf still share chunks (same file key and
chunk ids).

The Pi keeps an opaque reference list for GC:

| SQLite table | Columns | Purpose |
| --- | --- | --- |
| chunks | id, stored_size, created_at | What's on disk |
| objects | id, chunk_count, created_at | One per file version, random id, no name |
| object_chunks | object_id, chunk_index, chunk_id | Which chunks a version holds |

A write registers an object with its chunk list; deleting or overwriting a
file drops the old object. `oshelfd gc` removes chunks no object references,
keeping unreferenced chunks younger than 24 hours (uploads in flight).

## Encrypted manifest

The tree is one sealed snapshot at revision R plus a hash-chained log of
sealed entries R+1, R+2, and so on. The Pi stores both as opaque blobs and
only enforces that revisions go up by exactly one.

```
Node (CBOR)
  id          16 bytes, stable across rename and edit
  parent      16 bytes (root is all zeros)
  name        UTF-8, NFC normalized
  kind        file | dir | symlink
  size        u64 plaintext bytes
  mtime_ns    i64
  mode        u32 (POSIX bits for NFS)
  file_key    32 bytes (files only)
  chunk_size  u32, 1048576 in v1
  object_id   16 bytes, the server-side object holding this version
  chunks      [32 byte chunk id, ...]

LogEntry (CBOR)
  revision    u64
  prev_hash   32 bytes
  device_id   16 bytes
  time_ms     i64
  ops         [ put Node | delete id | move id -> parent, name ]
```

```
sealed_entry = "OSL1" || nonce (24) || XChaCha20-Poly1305(KM, nonce, zstd(cbor(entry)),
               aad = "OSL1" || u64le(revision) || prev_hash)
entry_hash   = BLAKE3(sealed_entry)
prev_hash of R+1 = entry_hash of R (or snapshot_hash for the first entry after a snapshot;
                   all zeros for revision 1)
```

Snapshots are sealed as 1 MiB segments in the chunk format, with key
HKDF(MK, "offshelf/v1/snapshot" || u64le(R)), plus a small sealed snapshot
header holding R, the chain hash at R, the segment ids, and the node count.
snapshot_hash is BLAKE3 of that sealed header.

Each client remembers the highest revision and hash it has verified. If the Pi
offers a lower revision, a different hash for a known revision, or a broken
chain, the client stops serving that tree and shows an error.

### Commit and conflicts

1. The client builds a LogEntry for head+1, seals it, uploads new chunks and
   the object first, then posts the entry with `If-Match: <head revision>`.
2. The Pi appends it if head still matches and pushes it on the event stream;
   otherwise it answers 409 with the current head, and the client fetches the
   entries it missed.
3. The client applies those entries, rebases its ops (last writer wins on the
   same path; the loser becomes "Name (conflict, Device)"), re-seals for the
   new revision, and retries.

### Revision check and compaction

`GET /v1/manifest/head` returns only the head revision and hash. A client more
than 10,000 entries or 64 MiB of log behind loads the latest snapshot instead.

A Mac compacts in the background: when the log since the last snapshot passes
5,000 entries or 32 MiB, it seals a snapshot at the current head and uploads
it. The Pi keeps the newest two snapshots and the log from the older one
onward.

## Device auth and pairing

Each device signs its requests with its Ed25519 key, because LAN traffic is
plain HTTP and a sniffed bearer token would let anyone delete the shelf.

```
Authorization: Oshelf device=<device_id hex>, ts=<unix ms>, sig=<base64>
sig = Ed25519(device_key, "OSR1" || method || "\n" || path_and_query || "\n"
              || ts || "\n" || BLAKE3(body))
```

The Pi rejects timestamps more than 60 seconds off and remembers signatures
inside that window to stop replays. Revoking a device deletes its public key.

Pairing:

1. `oshelf pair` on the Pi (or Pair in the web admin from a paired device)
   shows an 8 character code, valid 10 minutes, 5 attempts.
2. The new device generates its keypair and posts its public key and name with
   `HMAC-SHA256(code, "OSP1client" || pubkey || client_nonce)`.
3. The Pi answers with the device id, its server public key, and
   `HMAC-SHA256(code, "OSP1server" || server_pubkey || device_id || client_nonce)`.
   The HMAC key is the code uppercased with dashes and spaces removed. A
   wrong guess costs every live code one attempt.
4. The device pins the server public key, fetches the vault header, and
   unlocks with the passphrase (the first device runs init instead).

The browser pairs the same way once; the passphrase is asked per session
unless "stay unlocked 7 days" is on.

## Test vectors and fuzzing

Vectors live as JSON under `spec/vectors/`; the Rust core, Swift wrapper,
WebAssembly build, and server chunk checks must all pass them in CI.
Generation uses a fixed seed.

| Vector file | Covers |
| --- | --- |
| kdf.json | Argon2id passphrase key, HKDF subkeys |
| vault.json | Both slots, wrong passphrase, tampered slot |
| chunk.json | Empty, 1 byte, 1 MiB, 1 MiB + 1; wrong file id, wrong index, flipped bit, bad magic, nonzero reserved |
| range.json | Range to span and trim, edges at 0, 2^20, end of file |
| manifest.json | Node and LogEntry CBOR, sealed entries, 5 entry chain, broken chain, rollback |
| auth.json | Request signature, pairing HMACs |

cargo-fuzz runs nightly on chunk header parse and open, CBOR decode, log chain
verification, and the range mapper. Crash inputs become regression vectors.

## Decisions (2026-10-24)

- Random chunk nonces, not file id + index.
- Web app runs the Rust core as WebAssembly.
- Signed requests per device, not bearer tokens.
- Recovery key shown as 24 words.
- Argon2id stays at 256 MiB.
