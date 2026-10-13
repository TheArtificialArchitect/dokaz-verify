// Copyright 2026 Ian Lee
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. A copy is in this
// directory (LICENSE) and at http://www.apache.org/licenses/LICENSE-2.0

// Command dokaz-verify independently checks a Dokaz evidence PDF against
// its detached Ed25519 signature and the published public keys. It depends
// on the Go standard library only (crypto/ed25519, crypto/sha256,
// encoding/pem, encoding/json) — no Dokaz-specific code path — so any
// auditor can build it from this source and audit what they're trusting.
//
// Usage:
//
//	dokaz-verify --pdf=evidence.pdf --sig=signature.json --pubkey=dokaz.pem
//	dokaz-verify --log --sig=signature.json --pubkey=dokaz.pem [--pdf=evidence.pdf]
//
//	  --pdf      path to the evidence PDF downloaded from /v1/drills/{id}/evidence
//	  --sig      path to the signature JSON downloaded from /v1/drills/{id}/signature
//	  --pubkey   path to a PEM file holding one or more Ed25519 public keys.
//	             Dokaz publishes the active and every retired signing key at
//	             https://dokaz.net/.well-known/evidence-signing-keys.pem — pass
//	             that file as-is; the key whose fingerprint matches the
//	             signature's public_key_id is selected automatically.
//	  --log      check the signature's anchor in the Dokaz public transparency
//	             log instead of (or, with --pdf, as well as) the PDF: see below.
//
// Signature payloads are versioned by the "algorithm" field:
//
//	ed25519     (v1) hex(sha256(pdf)) "|" signed_at
//	ed25519-v2  (v2) "dokaz-evidence-v2\npdf_sha256=" hex "\nsigned_at=" signed_at
//	                 "\nretain_until=" retain_until      (also binds retention)
//	ed25519-v3  (v3) "dokaz-evidence-v3\npdf_sha256=" hex "\nsigned_at=" signed_at
//	                 "\nretain_until=" retain_until
//	                 "\nrto_seconds=" … "\nrpo_seconds=" … "\nbackup_at=" …
//	                 "\nbackup_at_source=" … "\nfetch_ms=" … "\nrestore_ms=" …
//	                 "\nrto_target_seconds=" … "\nrpo_target_seconds=" …
//	                 (also binds the measured recovery metrics: the
//	                 signature JSON's "recovery" object; null = empty value)
//
// Timestamps are RFC 3339 with nanoseconds, in UTC.
//
// Transparency log (--log). Dokaz appends every evidence signature to a
// public, append-only RFC 6962 Merkle log (origin "dokaz.net/log", served at
// https://dokaz.net/log/). Once a signed checkpoint covers it, the signature
// JSON carries a "log" object: leaf_index, leaf_entry, tree_size,
// inclusion_proof (base64 hashes, leaf sibling first) and checkpoint. --log
//
//  1. recomputes the leaf entry from the signature's own fields — one line,
//     "dokaz-evidence-log/v1 algorithm=<alg> public_key_id=<hex>
//     signature_sha256=<hex sha256 of the raw signature> pdf_sha256=<hex>
//     signed_at=<RFC 3339 nano, UTC>" — and requires it to equal leaf_entry;
//  2. verifies the checkpoint, a C2SP tlog-checkpoint signed note
//     (c2sp.org/tlog-checkpoint, c2sp.org/signed-note): origin, tree size,
//     base64 root hash, a "timestamp" extension line, then an Ed25519
//     signature line under key name "dokaz.net/log" from one of the --pubkey
//     keys (key ID = SHA-256(name || 0x0A || 0x01 || public key)[:4]);
//  3. verifies the inclusion proof of SHA-256(0x00 || entry) against the
//     checkpoint's root (nodes are SHA-256(0x01 || left || right)),
//
// then prints the anchor. With --pdf the PDF signature is verified first.
// The log is the anchor's whole point: it shows the evidence existed, signed,
// no later than the checkpoint, and monitors can confirm the log never
// rewrote history (GET /log/proof/consistency).
//
// Exit codes:
//
//	0   signature is valid (with --log: and anchored in the log)
//	1   signature is invalid (algorithm, digest, key, or Ed25519 check fails);
//	    with --log also: the log anchor does not verify
//	2   bad input (file missing, malformed JSON, no usable key, etc.); with
//	    --log also: the signature JSON has no anchor yet ("log": null)
//
// Mirrored verbatim to github.com/TheArtificialArchitect/dokaz-verify, where
// releases are built: change both together.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// version is set at release build time (-ldflags "-X main.version=...").
var version = "dev"

// buildVersion is the release tag, or for `go install …@vX` builds the module
// version recorded in the binary.
func buildVersion() string {
	if version == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			return bi.Main.Version
		}
	}
	return version
}

// KeysURL is where Dokaz publishes its evidence-signing public keys.
const KeysURL = "https://dokaz.net/.well-known/evidence-signing-keys.pem"

// signature is the wire shape returned by GET /v1/drills/{id}/signature.
// The field tags match the API exactly; future fields may be added but
// existing ones are stable.
type signature struct {
	Algorithm   string    `json:"algorithm"`
	PublicKeyID string    `json:"public_key_id"`
	Value       string    `json:"value"`
	PDFSHA256   string    `json:"pdf_sha256"`
	SignedAt    time.Time `json:"signed_at"`
	RetainUntil time.Time `json:"retain_until"`
	// Recovery is the measured recovery-metrics block, signed by v3.
	Recovery *recovery `json:"recovery"`
	// Log is the transparency-log anchor, kept raw: it is parsed only in
	// --log mode, so it can never change the plain verification's outcome.
	Log json.RawMessage `json:"log"`
}

// recovery is the "recovery" object of a v3 signature: RTO = fetch +
// restore wall-clock; RPO = drill start - backup_at (backup_at_source says
// where the backup time came from); the targets in force at drill start.
type recovery struct {
	RTOSeconds       *int64     `json:"rto_seconds"`
	RPOSeconds       *int64     `json:"rpo_seconds"`
	BackupAt         *time.Time `json:"backup_at"`
	BackupAtSource   *string    `json:"backup_at_source"`
	FetchMS          *int64     `json:"fetch_ms"`
	RestoreMS        *int64     `json:"restore_ms"`
	RTOTargetSeconds *int64     `json:"rto_target_seconds"`
	RPOTargetSeconds *int64     `json:"rpo_target_seconds"`
}

// canonical mirrors internal/evidence Recovery.canonical exactly.
func (r recovery) canonical() string {
	num := func(v *int64) string {
		if v == nil {
			return ""
		}
		return strconv.FormatInt(*v, 10)
	}
	backupAt, source := "", ""
	if r.BackupAt != nil {
		backupAt = r.BackupAt.UTC().Format(time.RFC3339Nano)
	}
	if r.BackupAtSource != nil {
		source = *r.BackupAtSource
	}
	return "\nrto_seconds=" + num(r.RTOSeconds) +
		"\nrpo_seconds=" + num(r.RPOSeconds) +
		"\nbackup_at=" + backupAt +
		"\nbackup_at_source=" + source +
		"\nfetch_ms=" + num(r.FetchMS) +
		"\nrestore_ms=" + num(r.RestoreMS) +
		"\nrto_target_seconds=" + num(r.RTOTargetSeconds) +
		"\nrpo_target_seconds=" + num(r.RPOTargetSeconds)
}

// summary is the one-line human rendering printed after OK.
func (r recovery) summary() string {
	num := func(v *int64, unit string) string {
		if v == nil {
			return "-"
		}
		return strconv.FormatInt(*v, 10) + unit
	}
	src := "-"
	if r.BackupAtSource != nil {
		src = *r.BackupAtSource
	}
	return "rto=" + num(r.RTOSeconds, "s") + " (target " + num(r.RTOTargetSeconds, "s") + ")" +
		"  rpo=" + num(r.RPOSeconds, "s") + " (target " + num(r.RPOTargetSeconds, "s") + ", backup_at_source=" + src + ")"
}

// envelope mirrors the Dokaz API response wrapper { data: ..., meta: ..., errors: ... }
// so the CLI accepts either the bare signature JSON or the wrapped form.
type envelope struct {
	Data *signature `json:"data"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main without the process exit, so tests can drive it.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dokaz-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pdfPath := fs.String("pdf", "", "path to the evidence PDF")
	sigPath := fs.String("sig", "", "path to the signature JSON")
	pubPath := fs.String("pubkey", "", "path to the PEM file of Ed25519 public keys ("+KeysURL+")")
	logMode := fs.Bool("log", false, "verify the signature's transparency-log anchor (checkpoint signature + inclusion proof); --pdf becomes optional")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "dokaz-verify "+buildVersion())
		return 0
	}
	if *logMode {
		return runLog(*pdfPath, *sigPath, *pubPath, stdout, stderr)
	}
	if *pdfPath == "" || *sigPath == "" || *pubPath == "" {
		fmt.Fprintln(stderr, "usage: dokaz-verify --pdf=PDF --sig=JSON --pubkey=PEM")
		fmt.Fprintln(stderr, "public keys: "+KeysURL)
		return 2
	}
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(stderr, format+"\n", a...)
		return code
	}

	pdf, err := os.ReadFile(*pdfPath)
	if err != nil {
		return fail(2, "read pdf: %v", err)
	}
	sigRaw, err := os.ReadFile(*sigPath)
	if err != nil {
		return fail(2, "read signature: %v", err)
	}
	pubPEM, err := os.ReadFile(*pubPath)
	if err != nil {
		return fail(2, "read pubkey: %v", err)
	}

	sig, err := parseSignature(sigRaw)
	if err != nil {
		return fail(2, "parse signature: %v", err)
	}
	keys, err := parsePublicKeys(pubPEM)
	if err != nil {
		return fail(2, "parse pubkey: %v", err)
	}

	// Select the key whose fingerprint the signature names. Never fall back
	// to "any key that verifies": the fingerprint ties the signature to one
	// published key, and the supplied file must contain it.
	pub, ok := keys[sig.PublicKeyID]
	if !ok {
		ids := make([]string, 0, len(keys))
		for id := range keys {
			ids = append(ids, id)
		}
		return fail(1, "FAIL: signature names key %s, which is not among the %d key(s) supplied (%s) — fetch the current key set from %s",
			sig.PublicKeyID, len(keys), strings.Join(ids, ", "), KeysURL)
	}

	if err := verify(pub, pdf, sig); err != nil {
		return fail(1, "FAIL: %v", err)
	}
	retention := "retain_until=" + sig.RetainUntil.UTC().Format(time.RFC3339)
	if sig.Algorithm == "ed25519" {
		retention += " (not covered by v1 signature)"
	}
	fmt.Fprintf(stdout, "OK  key=%s  alg=%s  signed_at=%s  %s\n",
		sig.PublicKeyID, sig.Algorithm, sig.SignedAt.UTC().Format(time.RFC3339), retention)
	if sig.Algorithm == "ed25519-v3" && sig.Recovery != nil {
		fmt.Fprintf(stdout, "    recovery (signed): %s\n", sig.Recovery.summary())
	}
	return 0
}

func parseSignature(raw []byte) (signature, error) {
	// Accept either the wrapped envelope or a bare signature object.
	var env envelope
	if err := json.Unmarshal(raw, &env); err == nil && env.Data != nil {
		return *env.Data, nil
	}
	var bare signature
	if err := json.Unmarshal(raw, &bare); err != nil {
		return signature{}, err
	}
	return bare, nil
}

// parsePublicKeys reads EVERY PEM block in the file (the published key set
// holds the active key plus retired ones, each preceded by comment lines)
// and returns the Ed25519 keys keyed by fingerprint. Blocks that are not
// Ed25519 public keys are skipped; a file with none is an error.
func parsePublicKeys(pemBytes []byte) (map[string]ed25519.PublicKey, error) {
	keys := map[string]ed25519.PublicKey{}
	var skipped []string
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s block: %v", block.Type, err))
			continue
		}
		pub, ok := parsed.(ed25519.PublicKey)
		if !ok {
			skipped = append(skipped, fmt.Sprintf("%T key", parsed))
			continue
		}
		keys[keyID(pub)] = pub
	}
	if len(keys) == 0 {
		if len(skipped) > 0 {
			return nil, fmt.Errorf("no Ed25519 public key found (skipped: %s)", strings.Join(skipped, "; "))
		}
		return nil, errors.New("pubkey file contains no PEM blocks")
	}
	return keys, nil
}

// verify mirrors evidence.Verify in the main repo exactly. Reimplemented
// here (rather than imported) so the CLI is small, has no transitive
// dependencies on Dokaz packages, and can be audited in isolation.
func verify(pub ed25519.PublicKey, pdf []byte, sig signature) error {
	digest := sha256.Sum256(pdf)
	hexDigest := hex.EncodeToString(digest[:])
	var msg []byte
	switch sig.Algorithm {
	case "ed25519": // v1 — identical to internal/evidence signedMessageV1
		msg = []byte(hexDigest + "|" + sig.SignedAt.UTC().Format(time.RFC3339Nano))
	case "ed25519-v2": // v2 — identical to internal/evidence signedMessageV2
		msg = []byte("dokaz-evidence-v2\npdf_sha256=" + hexDigest +
			"\nsigned_at=" + sig.SignedAt.UTC().Format(time.RFC3339Nano) +
			"\nretain_until=" + sig.RetainUntil.UTC().Format(time.RFC3339Nano))
	case "ed25519-v3": // v3 — identical to internal/evidence signedMessageV3
		if sig.Recovery == nil {
			return errors.New(`ed25519-v3 signature JSON has no "recovery" object`)
		}
		msg = []byte("dokaz-evidence-v3\npdf_sha256=" + hexDigest +
			"\nsigned_at=" + sig.SignedAt.UTC().Format(time.RFC3339Nano) +
			"\nretain_until=" + sig.RetainUntil.UTC().Format(time.RFC3339Nano) +
			sig.Recovery.canonical())
	default:
		return fmt.Errorf("unsupported algorithm %q", sig.Algorithm)
	}
	if hexDigest != sig.PDFSHA256 {
		return fmt.Errorf("PDF digest does not match signature (got %s, want %s — tampered or wrong file)",
			hexDigest, sig.PDFSHA256)
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("signature is not valid base64: %w", err)
	}
	if !ed25519.Verify(pub, msg, raw) {
		return errors.New("Ed25519 signature does not verify under the published key")
	}
	return nil
}

func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// --- transparency log (--log) ---------------------------------------------

// LogOrigin is the Dokaz transparency log's origin: the first line of every
// checkpoint and the key name its signature line carries.
const LogOrigin = "dokaz.net/log"

// logAnchor is the "log" object of the signature JSON.
type logAnchor struct {
	Origin         string   `json:"origin"`
	LeafIndex      int64    `json:"leaf_index"`
	LeafEntry      string   `json:"leaf_entry"`
	TreeSize       int64    `json:"tree_size"`
	InclusionProof []string `json:"inclusion_proof"`
	Checkpoint     string   `json:"checkpoint"`
}

// checkpoint is a verified tree head.
type checkpoint struct {
	Size      int64
	Root      [32]byte
	Timestamp string // the "timestamp" extension line's value, if any
	KeyID     string // fingerprint of the --pubkey key that signed it
}

// runLog is --log mode: optionally the plain PDF check, then the anchor.
func runLog(pdfPath, sigPath, pubPath string, stdout, stderr io.Writer) int {
	if sigPath == "" || pubPath == "" {
		fmt.Fprintln(stderr, "usage: dokaz-verify --log --sig=JSON --pubkey=PEM [--pdf=PDF]")
		fmt.Fprintln(stderr, "public keys: "+KeysURL)
		return 2
	}
	if pdfPath != "" {
		if code := run([]string{"--pdf=" + pdfPath, "--sig=" + sigPath, "--pubkey=" + pubPath}, stdout, stderr); code != 0 {
			return code
		}
	}
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(stderr, format+"\n", a...)
		return code
	}
	sigRaw, err := os.ReadFile(sigPath)
	if err != nil {
		return fail(2, "read signature: %v", err)
	}
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		return fail(2, "read pubkey: %v", err)
	}
	sig, err := parseSignature(sigRaw)
	if err != nil {
		return fail(2, "parse signature: %v", err)
	}
	keys, err := parsePublicKeys(pubPEM)
	if err != nil {
		return fail(2, "parse pubkey: %v", err)
	}
	raw := strings.TrimSpace(string(sig.Log))
	if raw == "" || raw == "null" {
		return fail(2, `signature JSON has no transparency-log anchor ("log" is null or absent): no checkpoint covers it yet; fetch the signature again after the next checkpoint (every 10 minutes)`)
	}
	var a logAnchor
	if err := json.Unmarshal(sig.Log, &a); err != nil {
		return fail(2, "parse log anchor: %v", err)
	}
	cp, err := verifyAnchor(sig, a, keys)
	if err != nil {
		return fail(1, "FAIL: log anchor: %v", err)
	}
	fmt.Fprintf(stdout, "ANCHORED  log=%s  index=%d  tree_size=%d  root=%s\n",
		LogOrigin, a.LeafIndex, cp.Size, base64.StdEncoding.EncodeToString(cp.Root[:]))
	fmt.Fprintf(stdout, "    checkpoint signed by key=%s  timestamp=%s\n", cp.KeyID, orDash(cp.Timestamp))
	fmt.Fprintf(stdout, "    entry: %s\n", a.LeafEntry)
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// verifyAnchor checks a log anchor end to end against the signature it
// claims to anchor and the published keys.
func verifyAnchor(sig signature, a logAnchor, keys map[string]ed25519.PublicKey) (checkpoint, error) {
	if a.Origin != LogOrigin {
		return checkpoint{}, fmt.Errorf("origin %q is not %s", a.Origin, LogOrigin)
	}
	entry, err := logEntry(sig)
	if err != nil {
		return checkpoint{}, err
	}
	if entry != a.LeafEntry {
		return checkpoint{}, fmt.Errorf("leaf_entry does not match this signature:\n  computed %s\n  anchor   %s", entry, a.LeafEntry)
	}
	cp, err := openCheckpoint([]byte(a.Checkpoint), keys)
	if err != nil {
		return checkpoint{}, err
	}
	if cp.Size != a.TreeSize {
		return checkpoint{}, fmt.Errorf("tree_size %d does not match the checkpoint's %d", a.TreeSize, cp.Size)
	}
	proof := make([][32]byte, len(a.InclusionProof))
	for i, p := range a.InclusionProof {
		b, err := base64.StdEncoding.Strict().DecodeString(p)
		if err != nil || len(b) != 32 {
			return checkpoint{}, fmt.Errorf("inclusion_proof[%d] is not a base64 SHA-256 hash", i)
		}
		copy(proof[i][:], b)
	}
	if err := verifyInclusion(a.LeafIndex, cp.Size, leafHash([]byte(entry)), proof, cp.Root); err != nil {
		return checkpoint{}, err
	}
	return cp, nil
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// logEntry recomputes the canonical leaf entry for a signature; mirrors
// internal/tlog Entry.Marshal in the main repo exactly.
func logEntry(sig signature) (string, error) {
	switch sig.Algorithm {
	case "ed25519", "ed25519-v2", "ed25519-v3":
	default:
		return "", fmt.Errorf("algorithm %q cannot be in the log", sig.Algorithm)
	}
	if !hex64.MatchString(sig.PublicKeyID) || !hex64.MatchString(sig.PDFSHA256) {
		return "", errors.New("public_key_id and pdf_sha256 must be 64 lowercase hex characters")
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return "", errors.New("signature value is not a base64 Ed25519 signature")
	}
	if sig.SignedAt.IsZero() {
		return "", errors.New("signed_at is missing")
	}
	sum := sha256.Sum256(raw)
	return "dokaz-evidence-log/v1" +
		" algorithm=" + sig.Algorithm +
		" public_key_id=" + sig.PublicKeyID +
		" signature_sha256=" + hex.EncodeToString(sum[:]) +
		" pdf_sha256=" + sig.PDFSHA256 +
		" signed_at=" + sig.SignedAt.UTC().Format(time.RFC3339Nano), nil
}

// leafHash and nodeHash are the RFC 6962 Merkle tree hashes.
func leafHash(entry []byte) [32]byte {
	return sha256.Sum256(append([]byte{0x00}, entry...))
}

func nodeHash(l, r [32]byte) [32]byte {
	b := make([]byte, 0, 65)
	b = append(b, 0x01)
	b = append(b, l[:]...)
	b = append(b, r[:]...)
	return sha256.Sum256(b)
}

// verifyInclusion checks an RFC 6962 audit path (RFC 9162 section 2.1.3.2).
func verifyInclusion(index, size int64, leaf [32]byte, proof [][32]byte, root [32]byte) error {
	if index < 0 || size < 1 || index >= size {
		return fmt.Errorf("leaf_index %d is outside tree size %d", index, size)
	}
	fn, sn := uint64(index), uint64(size-1)
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return errors.New("inclusion proof is too long")
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return errors.New("inclusion proof is too short")
	}
	if r != root {
		return errors.New("inclusion proof does not lead to the checkpoint's root hash")
	}
	return nil
}

// noteKeyID is the c2sp.org/signed-note Ed25519 key ID:
// SHA-256(name || 0x0A || 0x01 || public key)[:4], big-endian.
func noteKeyID(name string, pub ed25519.PublicKey) uint32 {
	b := append([]byte(name), '\n', 0x01)
	sum := sha256.Sum256(append(b, pub...))
	return binary.BigEndian.Uint32(sum[:4])
}

// openCheckpoint verifies a C2SP checkpoint signed note under the log origin
// with one of keys, then parses its text. Signature lines from other key
// names or unknown keys are ignored; a known key whose signature fails
// rejects the note.
func openCheckpoint(note []byte, keys map[string]ed25519.PublicKey) (checkpoint, error) {
	if !utf8.Valid(note) {
		return checkpoint{}, errors.New("checkpoint is not valid UTF-8")
	}
	for _, c := range note {
		if c < 0x20 && c != '\n' {
			return checkpoint{}, errors.New("checkpoint contains control characters")
		}
	}
	sep := bytes.LastIndex(note, []byte("\n\n"))
	if sep < 0 {
		return checkpoint{}, errors.New("checkpoint has no signature block")
	}
	text, sigs := note[:sep+1], note[sep+2:]
	if len(sigs) == 0 || sigs[len(sigs)-1] != '\n' {
		return checkpoint{}, errors.New("checkpoint signature block is malformed")
	}
	var cp checkpoint
	for _, line := range strings.Split(string(sigs[:len(sigs)-1]), "\n") {
		rest, ok := strings.CutPrefix(line, "— ") // em dash, space
		if !ok {
			return checkpoint{}, fmt.Errorf("malformed checkpoint signature line %q", line)
		}
		name, b64, ok := strings.Cut(rest, " ")
		if !ok {
			return checkpoint{}, fmt.Errorf("malformed checkpoint signature line %q", line)
		}
		blob, err := base64.StdEncoding.Strict().DecodeString(b64)
		if err != nil || len(blob) < 4 {
			return checkpoint{}, fmt.Errorf("malformed checkpoint signature on line %q", line)
		}
		if name != LogOrigin {
			continue
		}
		id := binary.BigEndian.Uint32(blob[:4])
		for fp, pub := range keys {
			if noteKeyID(name, pub) != id {
				continue
			}
			if !ed25519.Verify(pub, text, blob[4:]) {
				return checkpoint{}, fmt.Errorf("checkpoint signature does not verify under key %s", fp)
			}
			cp.KeyID = fp
		}
	}
	if cp.KeyID == "" {
		return checkpoint{}, fmt.Errorf("checkpoint is not signed by any supplied key under %q; fetch the current key set from %s", LogOrigin, KeysURL)
	}
	lines := strings.Split(string(text[:len(text)-1]), "\n")
	if len(lines) < 3 || lines[0] != LogOrigin {
		return checkpoint{}, fmt.Errorf("checkpoint body is not a %s checkpoint", LogOrigin)
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || size < 1 || strconv.FormatInt(size, 10) != lines[1] {
		return checkpoint{}, fmt.Errorf("checkpoint tree size %q is invalid", lines[1])
	}
	root, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || len(root) != 32 {
		return checkpoint{}, fmt.Errorf("checkpoint root hash %q is invalid", lines[2])
	}
	cp.Size = size
	copy(cp.Root[:], root)
	for _, ext := range lines[3:] {
		if ts, ok := strings.CutPrefix(ext, "timestamp "); ok {
			cp.Timestamp = ts
		}
	}
	return cp, nil
}
