// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package webauthntest provides WebAuthn ceremony fixtures for OIAF tests.
// It builds cryptographically valid registration (attestation) and
// authentication (assertion) responses using a real ES256 key pair, so tests
// exercise the full go-webauthn verification path instead of mocked data.
//
// This package is only imported from _test.go files and is never linked into
// production binaries.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// Test Relying Party parameters. "localhost" is explicitly permitted by the
// go-webauthn RPID validator, which keeps fixtures usable without a real DNS name.
const (
	RPID   = "localhost"
	Origin = "http://localhost:8080"
)

// Authenticator is a software test authenticator holding one ES256 credential.
type Authenticator struct {
	Key     *ecdsa.PrivateKey
	CredID  []byte
	AAGUID  []byte
	Counter uint32

	// NoUserVerified makes the authenticator omit the UV flag from its
	// authenticator data, emulating a device that performed only user-presence
	// (touch) without PIN/biometric verification. Use it to test that a
	// server configured with userVerification=required rejects such a
	// ceremony. Defaults to false (UV is reported), so existing fixtures are
	// unaffected.
	NoUserVerified bool
}

// NewAuthenticator creates a fresh software authenticator with a random
// credential ID.
func NewAuthenticator() *Authenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		panic(err)
	}
	return &Authenticator{Key: key, CredID: credID, AAGUID: make([]byte, 16)}
}

// COSEPublicKey returns the credential public key in COSE_Key CBOR encoding
// (kty=EC2, alg=ES256, crv=P-256).
func (a *Authenticator) COSEPublicKey() []byte {
	cose := map[int64]any{
		1:  int64(2),  // kty: EC2
		3:  int64(-7), // alg: ES256
		-1: int64(1),  // crv: P-256
		-2: padded32(a.Key.PublicKey.X),
		-3: padded32(a.Key.PublicKey.Y),
	}
	data, err := webauthncbor.Marshal(cose)
	if err != nil {
		panic(err)
	}
	return data
}

// CreationResponse builds a valid navigator.credentials.create() result for a
// registration ceremony. The challenge must be the exact base64url string the
// server issued in the PublicKeyCredentialCreationOptions.
func (a *Authenticator) CreationResponse(challenge, origin, rpID string) []byte {
	clientData := mustJSON(map[string]any{
		"type":        "webauthn.create",
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})

	authData := a.registrationAuthData(rpID, 0)

	attestationObject, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		panic(err)
	}

	return mustJSON(map[string]any{
		"id":    b64(a.CredID),
		"rawId": b64(a.CredID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"attestationObject": b64(attestationObject),
			"transports":        []string{"internal"},
		},
	})
}

// AssertionResponse builds a valid navigator.credentials.get() result for an
// authentication ceremony, signed with the authenticator's private key. The
// signature counter increments on every call, mirroring a real authenticator.
// userHandle must be the opaque user ID the server knows (WebAuthnID bytes).
func (a *Authenticator) AssertionResponse(challenge, origin, rpID string, userHandle []byte) []byte {
	a.Counter++

	clientData := mustJSON(map[string]any{
		"type":        "webauthn.get",
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})

	authData := a.assertionAuthData(rpID)

	clientDataHash := sha256.Sum256(clientData)
	sigData := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(sigData)
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	if err != nil {
		panic(err)
	}

	resp := map[string]any{
		"clientDataJSON":    b64(clientData),
		"authenticatorData": b64(authData),
		"signature":         b64(sig),
	}
	if len(userHandle) > 0 {
		resp["userHandle"] = b64(userHandle)
	}

	return mustJSON(map[string]any{
		"id":       b64(a.CredID),
		"rawId":    b64(a.CredID),
		"type":     "public-key",
		"response": resp,
	})
}

// registrationAuthData builds authenticator data for a registration ceremony:
// rpIdHash || flags (UP|AT[|UV]) || counter || aaguid || credIDLen || credID || COSE key.
func (a *Authenticator) registrationAuthData(rpID string, counter uint32) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	buf := make([]byte, 0, 37+16+2+len(a.CredID)+len(a.COSEPublicKey()))
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, a.registrationFlags())
	buf = binary.BigEndian.AppendUint32(buf, counter)
	buf = append(buf, a.AAGUID...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(a.CredID)))
	buf = append(buf, a.CredID...)
	buf = append(buf, a.COSEPublicKey()...)
	return buf
}

// assertionAuthData builds the 37-byte authenticator data for an assertion:
// rpIdHash || flags || counter. Flags are UP|UV (0x05), or UP alone (0x01) when
// NoUserVerified is set.
func (a *Authenticator) assertionAuthData(rpID string) []byte {
	rpIDHash := sha256.Sum256([]byte(rpID))
	buf := make([]byte, 0, 37)
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, a.assertionFlags())
	buf = binary.BigEndian.AppendUint32(buf, a.Counter)
	return buf
}

// assertionFlags returns the authenticator flags byte for an assertion:
// user present (0x01) always, user verified (0x04) unless NoUserVerified.
func (a *Authenticator) assertionFlags() byte {
	const (
		flagUserPresent  byte = 0x01
		flagUserVerified byte = 0x04
	)
	if a.NoUserVerified {
		return flagUserPresent
	}
	return flagUserPresent | flagUserVerified
}

// registrationFlags returns the authenticator flags byte for a registration:
// user present + attested credential data (0x41), plus user verified (0x04)
// unless NoUserVerified.
func (a *Authenticator) registrationFlags() byte {
	const (
		flagUserPresent      byte = 0x01
		flagUserVerified     byte = 0x04
		flagAttestedCredData byte = 0x40
	)
	flags := flagUserPresent | flagAttestedCredData
	if !a.NoUserVerified {
		flags |= flagUserVerified
	}
	return flags
}

func padded32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func mustJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
