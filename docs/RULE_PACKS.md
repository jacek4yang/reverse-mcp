# Rule Packs (issue #47)

Extensible, auditable intelligence rules for the crypto-constant scanner
and (planned) API-hash/string rules. Rules are **data only** — a pack can
never execute code. Loading is fail-closed: a malformed pack is rejected
with a precise error (file + reason) and the broker/worker keep running on
the built-in pack.

## Location

Packs live in `<exe dir>/rules/*.json` (non-recursive, same portable layout
policy as `plugins/`). If the directory is missing or empty, the
**built-in pack** is used: it is generated from the compiled-in `#12`
constant set, so behavior is a superset of reverse-mcp ≤ #12.

## Format (version 1)

```json
{
  "format": 1,
  "name": "my-pack",
  "version": "1.0",
  "source": "https://example.com/packs/my-pack",
  "enabled": true,
  "rules": [ ... ]
}
```

| field     | required | meaning                                              |
|-----------|----------|------------------------------------------------------|
| `format`  | yes      | must be `1`                                          |
| `name`    | yes      | pack identifier (shows in every hit's provenance)    |
| `version` | no       | free-form                                            |
| `source`  | no       | where the pack came from                             |
| `enabled` | no       | pack-level on/off (default `true`)                   |
| `rules`   | yes      | array of rules, max 10 000                           |

### Rule kinds

**`constant`** — byte pattern (crypto tables, magic qwords, float bytes):

```json
{
  "kind": "constant",
  "id": "my.aes-sbox-head",
  "hex": "637c777bf26b6fc5",
  "label": "AES S-box (head)",
  "table_size": 256,
  "rarity": 0.99
}
```

- `hex`: 1..4096 bytes (whitespace allowed).
- `rarity`: 0.1..1.0, feeds hit confidence (default 0.9).

**`string`** — literal (regex is deliberately NOT supported in v1 so load
time is deterministic and fail-closed):

```json
{ "kind": "string", "id": "my.badsign", "literal": "BADSIGN_v2", "encoding": "ascii" }
```

- `literal`: 1..1024 chars, no control characters.

**`api_hash`** — parameterized hash family:

```json
{
  "kind": "api_hash",
  "id": "my.ror13-var",
  "algo": "ror13-add",
  "seed": 0,
  "rotate": 13,
  "candidates": ["LoadLibraryA", "GetProcAddress"]
}
```

- `algo` must name a registered primitive (`ror13-add`, `ror13-add-wide`,
  `ror15-add`, `rol7-xor`, `crc32`). An unknown algo rejects the whole pack
  at LOAD (never a runtime crash).
- `candidates`: 1..256 names.

### Rule ids

Unique within a pack; shape `[A-Za-z0-9_.:-]{1,128}`. They are the stable
half of a hit's provenance — the other half is the pack file's FNV-1a
fingerprint recorded at load.

## Provenance

Every scan hit carries:

```json
{ "pack": "my-pack", "pack_sha256": "1a2b3c…", "rule": "my.aes-sbox-head", "label": "AES S-box (head)" }
```

so an agent can always answer "which rule, from which pack content".

## Scanning bounds

Same as #12: 1 MiB chunks, 64 MiB per-segment cap, `max_findings` clamps
the result (4× overscan for ranking). Per-pack rule counts are capped at
load; a 10 000-rule pack loads and scans within the same bounded walk.

## Caching

`intel.crypto` results are cached per (pack-set fingerprint + revision).
Unchanged DB + unchanged packs → `cached: true`; any mutation or pack
change re-scans.
