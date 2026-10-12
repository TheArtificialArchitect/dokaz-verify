// Copyright 2026 Ian Lee
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. A copy is in this
// directory (LICENSE) and at http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The vectors in testdata/ were produced by the production Dokaz signer
// (not by this verifier), from fixed test keys, so these tests check the
// verifier against what the service actually emits. keys.pem is a rotated
// key set: the active key first, the retired key second.

func runCLI(t *testing.T, pdf, sig, keys string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run([]string{"--pdf=" + pdf, "--sig=" + sig, "--pubkey=" + keys}, &out, &errb)
	return code, out.String() + errb.String()
}

func td(name string) string { return filepath.Join("testdata", name) }

// mutated copies a testdata signature with one field changed.
func mutated(t *testing.T, name, field string, value any) string {
	t.Helper()
	raw, err := os.ReadFile(td(name))
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env["data"][field] = value
	b, _ := json.Marshal(env)
	path := filepath.Join(t.TempDir(), "sig.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVectorsVerify(t *testing.T) {
	for _, tc := range []struct{ sig, alg string }{
		{"signature-v1.json", "alg=ed25519 "},
		{"signature-v2.json", "alg=ed25519-v2"},        // retired key: second PEM block
		{"signature-v2-active.json", "alg=ed25519-v2"}, // active key: first PEM block
		{"signature-v3.json", "alg=ed25519-v3"},        // + signed recovery metrics
		{"signature-v3-sparse.json", "alg=ed25519-v3"}, // nulls sign as empty values
	} {
		code, out := runCLI(t, td("evidence.pdf"), td(tc.sig), td("keys.pem"))
		if code != 0 || !strings.HasPrefix(out, "OK") || !strings.Contains(out, tc.alg) {
			t.Errorf("%s: code=%d out=%s", tc.sig, code, out)
		}
	}
}

func TestV1SaysRetentionUncovered(t *testing.T) {
	_, out := runCLI(t, td("evidence.pdf"), td("signature-v1.json"), td("keys.pem"))
	if !strings.Contains(out, "not covered by v1") {
		t.Fatalf("v1 output must say retain_until is unsigned: %s", out)
	}
}

func TestRejectsTamperedPDF(t *testing.T) {
	pdf, _ := os.ReadFile(td("evidence.pdf"))
	path := filepath.Join(t.TempDir(), "e.pdf")
	_ = os.WriteFile(path, append(pdf, ' '), 0o600)
	if code, out := runCLI(t, path, td("signature-v2.json"), td("keys.pem")); code != 1 {
		t.Fatalf("one extra byte must fail: code=%d out=%s", code, out)
	}
}

func TestRejectsAlteredRetainUntil(t *testing.T) {
	sig := mutated(t, "signature-v2.json", "retain_until", "2026-10-13T09:30:00.123456Z")
	if code, out := runCLI(t, td("evidence.pdf"), sig, td("keys.pem")); code != 1 {
		t.Fatalf("shortened retain_until must fail: code=%d out=%s", code, out)
	}
}

func TestRejectsAlteredSignedAt(t *testing.T) {
	sig := mutated(t, "signature-v2.json", "signed_at", "2026-10-12T09:30:01.123456Z")
	if code, out := runCLI(t, td("evidence.pdf"), sig, td("keys.pem")); code != 1 {
		t.Fatalf("altered signed_at must fail: code=%d out=%s", code, out)
	}
}

func TestRejectsUnknownKey(t *testing.T) {
	sig := mutated(t, "signature-v2.json", "public_key_id", strings.Repeat("ab", 32))
	code, out := runCLI(t, td("evidence.pdf"), sig, td("keys.pem"))
	if code != 1 || !strings.Contains(out, "not among") {
		t.Fatalf("unpublished key: code=%d out=%s", code, out)
	}
}

// A signature must verify only under the key it names: the v2 vector was
// made by the retired key, so naming the active key must fail.
func TestRejectsWrongNamedKey(t *testing.T) {
	sig := mutated(t, "signature-v2.json", "public_key_id",
		"b9797df8f3ca9efc162a9d991e051001b93eaa41a908cfe4978b554fb6842b14")
	if code, out := runCLI(t, td("evidence.pdf"), sig, td("keys.pem")); code != 1 {
		t.Fatalf("signature under a different named key must fail: code=%d out=%s", code, out)
	}
}

func TestRejectsUnknownAlgorithm(t *testing.T) {
	sig := mutated(t, "signature-v2.json", "algorithm", "ed25519-v9")
	if code, out := runCLI(t, td("evidence.pdf"), sig, td("keys.pem")); code != 1 {
		t.Fatalf("unknown algorithm must fail: code=%d out=%s", code, out)
	}
}

func TestUsageNamesDokazKeyURL(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("no args: code=%d", code)
	}
	if !strings.Contains(errb.String(), KeysURL) {
		t.Fatalf("usage must point auditors at %s: %s", KeysURL, errb.String())
	}
}

func TestVersionFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--version"}, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "dokaz-verify ") {
		t.Fatalf("--version: code=%d out=%q", code, out.String())
	}
}

// testdata/production-2026-10-12 is a real evidence PDF from dokaz.net (a
// sample-dataset drill on a throwaway test account), its signature from the
// API, and the key set published at KeysURL on that day. It pins the
// verifier to what production actually signs, not just to the test keys.
func TestProductionEvidence(t *testing.T) {
	dir := filepath.Join("testdata", "production-2026-10-12")
	code, out := runCLI(t, filepath.Join(dir, "evidence.pdf"), filepath.Join(dir, "signature.json"), filepath.Join(dir, "keys.pem"))
	if code != 0 || !strings.Contains(out, "key=e384c161032c3d57cd46925d67a84300618acaae9581b5be58fcbf714ce91177") {
		t.Fatalf("production evidence must verify under the published key: code=%d out=%s", code, out)
	}
}

func TestV3PrintsSignedRecovery(t *testing.T) {
	_, out := runCLI(t, td("evidence.pdf"), td("signature-v3.json"), td("keys.pem"))
	if !strings.Contains(out, "recovery (signed): rto=754s (target 3600s)") {
		t.Fatalf("v3 output must show the signed recovery metrics: %s", out)
	}
}

// Editing any recovery figure, or nulling one, must break a v3 signature.
func TestV3RejectsAlteredRecovery(t *testing.T) {
	for field, value := range map[string]any{
		"rto_seconds": 600, "rpo_seconds": nil, "rto_target_seconds": 7200,
		"backup_at": "2026-10-12T07:30:00.123456Z", "backup_at_source": "declared",
	} {
		raw, _ := os.ReadFile(td("signature-v3.json"))
		var env map[string]map[string]any
		_ = json.Unmarshal(raw, &env)
		env["data"]["recovery"].(map[string]any)[field] = value
		b, _ := json.Marshal(env)
		path := filepath.Join(t.TempDir(), "sig.json")
		_ = os.WriteFile(path, b, 0o600)
		if code, out := runCLI(t, td("evidence.pdf"), path, td("keys.pem")); code != 1 {
			t.Errorf("altered recovery.%s must fail: code=%d out=%s", field, code, out)
		}
	}
}

func TestV3RequiresRecoveryObject(t *testing.T) {
	sig := mutated(t, "signature-v3.json", "recovery", nil)
	if code, out := runCLI(t, td("evidence.pdf"), sig, td("keys.pem")); code != 1 {
		t.Fatalf("v3 without recovery must fail: code=%d out=%s", code, out)
	}
}
