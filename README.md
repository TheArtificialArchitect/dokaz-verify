# dokaz-verify

Independently check a [Dokaz](https://dokaz.net) restore-test evidence PDF.
You don't have to trust Dokaz to do it.

Every Dokaz drill produces a PDF and a detached Ed25519 signature. This tool
checks three things:

1. **The PDF is unaltered.** Its SHA-256 must match the signed digest.
2. **The signature is genuine.** It must verify under the published key it names.
3. **The signed details are unaltered.** For v2 signatures that includes the
   signing time and the retention date. For v3 it also includes the measured
   recovery metrics: RTO, RPO, backup time and its source, fetch and restore
   times, and the targets in force.

It is one Go file using only the standard library, so you can read all of it
before you run it.

## Install

Download a binary for your platform from
[Releases](https://github.com/TheArtificialArchitect/dokaz-verify/releases).
Check it against `SHA256SUMS` and the build-provenance attestation:

```sh
gh attestation verify dokaz-verify_linux_amd64 --repo TheArtificialArchitect/dokaz-verify
```

Or build from source (Go 1.22+):

```sh
go install github.com/TheArtificialArchitect/dokaz-verify@latest
```

## Use

```sh
curl -fsSO https://dokaz.net/.well-known/evidence-signing-keys.pem
dokaz-verify --pdf=evidence.pdf --sig=signature.json --pubkey=evidence-signing-keys.pem
```

- `evidence.pdf` comes from the drill page, or from `GET /v1/drills/{id}/evidence`.
- `signature.json` comes from `GET /v1/drills/{id}/signature`. The bare object
  and the `{"data": ...}` envelope are both accepted.
- The key file holds the active signing key and every retired one. The key the
  signature names is selected automatically. It never falls back to "any key
  that happens to verify".

| Exit code | Meaning |
|---|---|
| 0 | `OK`: valid |
| 1 | `FAIL`: tampered PDF, altered field, unknown key, or bad signature |
| 2 | Bad input |

## Check the public transparency log (`--log`)

Dokaz appends every evidence signature to a public, append-only
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) Merkle log, served at
<https://dokaz.net/log/checkpoint>. Once a signed checkpoint covers a report,
its signature JSON carries a `log` object: the leaf, an inclusion proof and
the checkpoint (a [C2SP signed note](https://c2sp.org/tlog-checkpoint) under
the key name `dokaz.net/log`).

```sh
dokaz-verify --log --sig=signature.json --pubkey=evidence-signing-keys.pem --pdf=evidence.pdf
```

This checks four things: the checkpoint is signed by a published key, the
leaf hashes into the checkpoint's root, the leaf names this exact signature
and PDF, and the evidence signature itself. A signature without an anchor
yet (`"log": null`, checkpoints are cut every few minutes) exits 2.

A log entry holds only hashes, the key fingerprint and the signing time.
It never holds customer names or identifiers. The checkpoint timestamp is
Dokaz's own clock; independent witnesses are planned.

## Signature formats

| `algorithm` | Signed message |
|---|---|
| `ed25519` (v1) | `hex(sha256(pdf)) + "\|" + signed_at` |
| `ed25519-v2` | `"dokaz-evidence-v2\npdf_sha256=" + hex + "\nsigned_at=" + signed_at + "\nretain_until=" + retain_until` |
| `ed25519-v3` | as v2 but prefixed `dokaz-evidence-v3`, then `"\nrto_seconds=" … "\nrpo_seconds=" … "\nbackup_at=" … "\nbackup_at_source=" … "\nfetch_ms=" … "\nrestore_ms=" … "\nrto_target_seconds=" … "\nrpo_target_seconds=" …` from the signatures `recovery` object (null = empty value) |

Timestamps are RFC 3339 with nanoseconds, in UTC.

## Test vectors

The test vectors were produced by Dokaz's production signer, not by this tool:

- `testdata/*.json` and `keys.pem` were made from fixed test keys, with a
  rotated key set.
- `testdata/production-2026-10-12/` is a real evidence PDF from dokaz.net, with
  its API signature and the key set published that day. The drill ran on the
  built-in sample dataset under a throwaway test account.

Run them with `go test ./...`.

## Source of truth

This repository mirrors `cmd/dokaz-verify` from the Dokaz service, which is
kept in sync with it. Please report security issues privately to
support@dokaz.net.

Licensed under Apache-2.0.
