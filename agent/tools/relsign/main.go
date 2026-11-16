// relsign — release-manifest signing tool for QuarkShield agent push-upgrades.
//
// The agent only applies a pushed upgrade whose manifest carries an Ed25519
// signature from a key compiled into the agent (agent/release_keys.go). The
// private key never touches the server, so a compromised console or database
// cannot make endpoints run anything other than a genuine release.
//
// Usage (run from agent/):
//
//	go run ./tools/relsign keygen <private-key-file>      create a key, print the public key
//	go run ./tools/relsign pubkey <private-key-file>      print the public key
//	go run ./tools/relsign sign   <private-key-file> <manifest.json>   writes <manifest.json>.sig
//	go run ./tools/relsign verify <public-key-b64>   <manifest.json>   checks <manifest.json>.sig
//
// The private key file holds the base64 Ed25519 seed. Keep it offline-backed-up
// and out of git (.env* and *.key are ignored).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "relsign: "+format+"\n", a...)
	os.Exit(1)
}

func loadKey(path string) ed25519.PrivateKey {
	raw, err := os.ReadFile(path)
	if err != nil {
		die("cannot read key file: %v", err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		die("key file is not a base64 Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed)
}

func pubB64(k ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

func main() {
	if len(os.Args) < 3 {
		die("usage: relsign keygen|pubkey <keyfile> | sign <keyfile> <manifest> | verify <pubkey-b64> <manifest>")
	}
	switch os.Args[1] {
	case "keygen":
		path := os.Args[2]
		if _, err := os.Stat(path); err == nil {
			die("%s already exists — refusing to overwrite a release key", path)
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			die("key generation failed: %v", err)
		}
		seed := base64.StdEncoding.EncodeToString(priv.Seed())
		if err := os.WriteFile(path, []byte(seed+"\n"), 0600); err != nil {
			die("cannot write key file: %v", err)
		}
		fmt.Println(pubB64(priv))
	case "pubkey":
		fmt.Println(pubB64(loadKey(os.Args[2])))
	case "sign":
		if len(os.Args) < 4 {
			die("usage: relsign sign <keyfile> <manifest>")
		}
		key := loadKey(os.Args[2])
		data, err := os.ReadFile(os.Args[3])
		if err != nil {
			die("cannot read manifest: %v", err)
		}
		sig := base64.StdEncoding.EncodeToString(ed25519.Sign(key, data))
		if err := os.WriteFile(os.Args[3]+".sig", []byte(sig+"\n"), 0644); err != nil {
			die("cannot write signature: %v", err)
		}
		fmt.Printf("signed %s with key %s\n", os.Args[3], pubB64(key))
	case "verify":
		if len(os.Args) < 4 {
			die("usage: relsign verify <pubkey-b64> <manifest>")
		}
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Args[2]))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			die("not a base64 Ed25519 public key")
		}
		data, err := os.ReadFile(os.Args[3])
		if err != nil {
			die("cannot read manifest: %v", err)
		}
		rawSig, err := os.ReadFile(os.Args[3] + ".sig")
		if err != nil {
			die("cannot read signature: %v", err)
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawSig)))
		if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
			die("signature does NOT verify")
		}
		fmt.Println("signature OK")
	default:
		die("unknown command %q", os.Args[1])
	}
}
