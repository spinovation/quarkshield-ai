package main

// Trust anchors for remote push-upgrade (see updater.go).
//
// releasePublicKeys are the base64 Ed25519 public keys allowed to sign a release
// manifest. The matching private key is held only on the release machine
// (agent/.env.release-key, git-ignored) and is used by build_all_and_sign.sh via
// `go run ./tools/relsign sign`. It is never deployed to the server.
//
// To rotate: add the new public key here, ship a release signed with the OLD key
// (so existing agents accept it and learn the new key), then sign later releases
// with the new key and remove the old one. If the private key is lost before a
// rotation, agents can only be upgraded by re-installing.
var releasePublicKeys = []string{
	"h8+moS3qnduP/OYxOucCngTB6ekj6Yo2oV1UkV7km0A=",
}

// Code-signing identities a pushed build must carry, in addition to the signed
// manifest: the Apple Developer ID team on macOS and the Authenticode publisher
// (Azure Trusted Signing) on Windows.
const (
	releaseAppleTeamID        = "4ADVSK467Z"
	releaseWindowsSubjectCN   = "CN=Fedmitigate LLC"
	releaseWindowsIssuerMatch = "CN=Microsoft ID Verified"
)
