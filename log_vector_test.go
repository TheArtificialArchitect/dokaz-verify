// Copyright 2026 Ian Lee
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. A copy is in this
// directory (LICENSE) and at http://www.apache.org/licenses/LICENSE-2.0

package main

// Standard library only: this test ships with the public dokaz-verify repo.
// testdata/log_vector.json was produced by the Dokaz server code (see
// log_server_test.go in the Dokaz repo): a signed evidence PDF, its
// signature JSON with a transparency-log anchor, and the published key set.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vectorFiles struct{ pdf, sig, keys string }

// loadVector writes the vector's files, letting edit rewrite the signature
// JSON's "data" object first.
func loadVector(t *testing.T, edit func(data map[string]any)) vectorFiles {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "log_vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		PDFBase64 string          `json:"pdf_base64"`
		KeysPEM   string          `json:"keys_pem"`
		Signature json.RawMessage `json:"signature"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pdf, err := base64.StdEncoding.DecodeString(v.PDFBase64)
	if err != nil {
		t.Fatal(err)
	}
	sig := []byte(v.Signature)
	if edit != nil {
		var env map[string]map[string]any
		if err := json.Unmarshal(sig, &env); err != nil {
			t.Fatal(err)
		}
		edit(env["data"])
		sig, _ = json.Marshal(env)
	}
	dir := t.TempDir()
	f := vectorFiles{filepath.Join(dir, "e.pdf"), filepath.Join(dir, "s.json"), filepath.Join(dir, "k.pem")}
	for p, b := range map[string][]byte{f.pdf: pdf, f.sig: sig, f.keys: []byte(v.KeysPEM)} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func runVector(args ...string) (int, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String() + errb.String()
}

func TestLogVectorVerifies(t *testing.T) {
	f := loadVector(t, nil)
	code, out := runVector("--log", "--sig="+f.sig, "--pubkey="+f.keys)
	if code != 0 || !strings.Contains(out, "ANCHORED  log=dokaz.net/log  index=4  tree_size=7") ||
		!strings.Contains(out, "timestamp=2026-10-12T09:40:00Z") {
		t.Fatalf("--log: code=%d\n%s", code, out)
	}
	code, out = runVector("--log", "--pdf="+f.pdf, "--sig="+f.sig, "--pubkey="+f.keys)
	if code != 0 || !strings.Contains(out, "OK  key=") || !strings.Contains(out, "ANCHORED") {
		t.Fatalf("--log --pdf: code=%d\n%s", code, out)
	}
	// Without --log the anchored signature verifies exactly as before.
	code, out = runVector("--pdf="+f.pdf, "--sig="+f.sig, "--pubkey="+f.keys)
	if code != 0 || strings.Contains(out, "ANCHORED") {
		t.Fatalf("plain: code=%d\n%s", code, out)
	}
}

func TestLogVectorTampered(t *testing.T) {
	anchor := func(d map[string]any) map[string]any { return d["log"].(map[string]any) }
	flipFirst := func(b64 string) string {
		raw, _ := base64.StdEncoding.DecodeString(b64)
		raw[0] ^= 0x80
		return base64.StdEncoding.EncodeToString(raw)
	}
	for name, edit := range map[string]func(map[string]any){
		"proof hash flipped": func(d map[string]any) {
			p := anchor(d)["inclusion_proof"].([]any)
			p[0] = flipFirst(p[0].(string))
		},
		"proof reordered": func(d map[string]any) {
			p := anchor(d)["inclusion_proof"].([]any)
			p[0], p[1] = p[1], p[0]
		},
		"leaf index moved":   func(d map[string]any) { anchor(d)["leaf_index"] = 3 },
		"tree size inflated": func(d map[string]any) { anchor(d)["tree_size"] = 8 },
		"checkpoint size line edited": func(d map[string]any) {
			a := anchor(d)
			a["checkpoint"] = strings.Replace(a["checkpoint"].(string), "\n7\n", "\n8\n", 1)
			a["tree_size"] = 8
		},
		"checkpoint signature line dropped": func(d map[string]any) {
			a := anchor(d)
			cp := a["checkpoint"].(string)
			a["checkpoint"] = cp[:strings.LastIndex(cp, "\n\n")+2] + "— dokaz.net/log AAAAAA==\n"
		},
		"pdf digest swapped":  func(d map[string]any) { d["pdf_sha256"] = strings.Repeat("a", 64) },
		"key id swapped":      func(d map[string]any) { d["public_key_id"] = strings.Repeat("b", 64) },
		"algorithm relabeled": func(d map[string]any) { d["algorithm"] = "ed25519-v2" },
	} {
		f := loadVector(t, edit)
		if code, out := runVector("--log", "--sig="+f.sig, "--pubkey="+f.keys); code != 1 {
			t.Errorf("%s: want exit 1, got %d\n%s", name, code, out)
		}
	}

	f := loadVector(t, func(d map[string]any) { d["log"] = nil })
	if code, out := runVector("--log", "--sig="+f.sig, "--pubkey="+f.keys); code != 2 {
		t.Errorf("null anchor: want exit 2, got %d\n%s", code, out)
	}
}
