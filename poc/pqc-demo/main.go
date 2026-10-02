// QuarkShield — Pure-PQC Proof of Concept (Track 2).
//
// Demonstrates CNSA 2.0 pure post-quantum data protection on NIST FIPS 203/204
// algorithms, with NO hybrid, NO pre-shared keys, and client-side key custody:
//
//   1. Receiver generates an ML-KEM-1024 (FIPS 203) key pair.
//   2. Sender ENCAPSULATES a fresh shared secret to the receiver's public key.
//   3. The shared secret keys AES-256-GCM; the payload is encrypted.
//   4. Sender SIGNS the ciphertext with ML-DSA-87 (FIPS 204) for authenticity/provenance.
//   5. Receiver verifies the ML-DSA-87 signature, DECAPSULATES, and decrypts.
//
// PoC only — production uses FIPS-validated ML-KEM/ML-DSA modules (see Track-2 scoping).
// Build: go run .   |   go run . path/to/file
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func must(step string, err error) {
	if err != nil {
		fmt.Printf("   ✗ %s: %v\n", step, err)
		os.Exit(1)
	}
}

func main() {
	fmt.Println("======================================================================")
	fmt.Println(" QuarkShield — Pure-PQC Data Protection PoC  (CNSA 2.0 · FIPS 203/204)")
	fmt.Println("======================================================================")

	// Payload: a file if given, else a sample message.
	var payload []byte
	if len(os.Args) > 1 {
		b, err := os.ReadFile(os.Args[1])
		must("read file", err)
		payload = b
		fmt.Printf("\nPayload: %s (%d bytes)\n", os.Args[1], len(payload))
	} else {
		payload = []byte("CLASSIFIED // FedMitigate QuarkShield pure-PQC channel — harvest this all you want.")
		fmt.Printf("\nPayload: built-in sample (%d bytes)\n", len(payload))
	}

	kem := mlkem1024.Scheme()
	sig := mldsa87.Scheme()

	// --- 1. Receiver key pair (ML-KEM-1024) — keys held client-side, no third party ---
	recvPub, recvPriv, err := kem.GenerateKeyPair()
	must("ML-KEM keygen", err)
	pkBytes, _ := recvPub.MarshalBinary()
	fmt.Printf("\n[1] Receiver ML-KEM-1024 key pair generated.\n")
	fmt.Printf("    public key: %d bytes (FIPS 203)\n", len(pkBytes))

	// --- 2. Sender ML-DSA-87 identity key (provenance / authentication) ---
	signPub, signPriv, err := sig.GenerateKey()
	must("ML-DSA keygen", err)
	fmt.Printf("[2] Sender ML-DSA-87 identity key generated (FIPS 204).\n")

	// --- 3. Sender ENCAPSULATES a shared secret to the receiver (no PSK, no hybrid) ---
	ct, sharedSecret, err := kem.Encapsulate(recvPub)
	must("ML-KEM encapsulate", err)
	fmt.Printf("[3] ML-KEM-1024 encapsulation → shared secret %d bytes, ciphertext %d bytes.\n", len(sharedSecret), len(ct))

	// --- 4. AES-256-GCM encrypt under the encapsulated secret ---
	block, err := aes.NewCipher(sharedSecret[:32])
	must("aes", err)
	gcm, err := cipher.NewGCM(block)
	must("gcm", err)
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	must("nonce", err)
	ciphertext := gcm.Seal(nil, nonce, payload, ct) // bind KEM ct as AAD
	fmt.Printf("[4] AES-256-GCM encrypted payload → %d bytes ciphertext.\n", len(ciphertext))

	// --- 5. Sender SIGNS the ciphertext (authenticity + provenance) ---
	signed := append(append([]byte{}, nonce...), ciphertext...)
	signature := sig.Sign(signPriv, signed, nil)
	fmt.Printf("[5] ML-DSA-87 signature over ciphertext → %d bytes.\n", len(signature))

	fmt.Println("\n--- wire: {kem_ct, nonce, aes_gcm_ciphertext, mldsa_signature} travels; harvest-now-decrypt-later is useless ---")

	// ================= RECEIVER SIDE =================
	fmt.Println("\n[6] Receiver verifies ML-DSA-87 signature...")
	if !sig.Verify(signPub, signed, signature, nil) {
		fmt.Println("    ✗ signature INVALID — reject.")
		os.Exit(1)
	}
	fmt.Println("    ✓ signature valid — sender authentic.")

	fmt.Println("[7] Receiver ML-KEM-1024 decapsulates the shared secret...")
	recovered, err := kem.Decapsulate(recvPriv, ct)
	must("ML-KEM decapsulate", err)
	rblock, _ := aes.NewCipher(recovered[:32])
	rgcm, _ := cipher.NewGCM(rblock)
	plain, err := rgcm.Open(nil, nonce, ciphertext, ct)
	must("aes-gcm open", err)

	fmt.Printf("[8] Decrypted plaintext (%d bytes):\n    %q\n", len(plain), string(plain))

	fmt.Println("\n======================================================================")
	if string(plain) == string(payload) {
		fmt.Println(" ✅ SUCCESS — pure ML-KEM-1024 + ML-DSA-87 + AES-256-GCM round-trip.")
		fmt.Println("    No hybrid. No pre-shared keys. Keys never left the endpoints.")
	} else {
		fmt.Println(" ✗ FAILURE — plaintext mismatch.")
		os.Exit(1)
	}
	fmt.Println("======================================================================")
}
