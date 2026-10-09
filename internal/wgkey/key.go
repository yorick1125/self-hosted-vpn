// Package wgkey generates and parses WireGuard keys using only the standard
// library, so wgm never has to shell out to `wg genkey` or pipe private keys
// through another process.
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

// Key is a 32-byte Curve25519 key (private, public or preshared).
type Key [32]byte

// String returns the base64 form WireGuard uses in config files.
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// IsZero reports whether k is the all-zero key.
func (k Key) IsZero() bool { return k == Key{} }

// ErrInvalidKey is returned for anything that is not 32 bytes of base64.
var ErrInvalidKey = errors.New("invalid WireGuard key: want 32 bytes, base64-encoded")

// Parse decodes a base64 key as found in a WireGuard config.
func Parse(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return Key{}, ErrInvalidKey
	}
	var k Key
	copy(k[:], b)
	return k, nil
}

// NewPrivate returns a clamped Curve25519 private key, identical in form to
// the output of `wg genkey`.
func NewPrivate() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

// NewPreshared returns 32 random bytes, identical in form to `wg genpsk`.
func NewPreshared() (Key, error) {
	var k Key
	_, err := rand.Read(k[:])
	return k, err
}

// Public derives the public key for private key k.
func (k Key) Public() (Key, error) {
	priv, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return Key{}, err
	}
	var pub Key
	copy(pub[:], priv.PublicKey().Bytes())
	return pub, nil
}
