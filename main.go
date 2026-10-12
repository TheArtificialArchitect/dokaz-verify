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
//
//	  --pdf      path to the evidence PDF downloaded from /v1/drills/{id}/evidence
//	  --sig      path to the signature JSON downloaded from /v1/drills/{id}/signature
//	  --pubkey   path to a PEM file holding one or more Ed25519 public keys.
//	             Dokaz publishes the active and every retired signing key at
//	             https://dokaz.net/.well-known/evidence-signing-keys.pem — pass
//	             that file as-is; the key whose fingerprint matches the
//	             signature's public_key_id is selected automatically.
//
// Signature payloads are versioned by the "algorithm" field:
//
//	ed25519     (v1) hex(sha256(pdf)) "|" signed_at
//	ed25519-v2  (v2) "dokaz-evidence-v2\npdf_sha256=" hex "\nsigned_at=" signed_at
//	                 "\nretain_until=" retain_until      (also binds retention)
//
// Timestamps are RFC 3339 with nanoseconds, in UTC.
//
// Exit codes:
//
//	0   signature is valid
//	1   signature is invalid (algorithm, digest, key, or Ed25519 check fails)
//	2   bad input (file missing, malformed JSON, no usable key, etc.)
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// version is set at release build time (-ldflags "-X main.version=...").
var version = "dev"

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
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "dokaz-verify "+version)
		return 0
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
