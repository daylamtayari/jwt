package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"os"
)

var (
	ErrInvalidAlg     = errors.New("invalid alg claim")
	ErrInvalidPEM     = errors.New("invalid PEM block")
	ErrInvalidSig     = errors.New("invalid JWT signature")
	ErrUnsupportedAlg = errors.New("unsupported algorithm")
)

// Verifies a JWT's signature with the providedd key
func Verify(jwt JWT, key string) error {
	alg, ok := jwt.Header["alg"].(string)
	if !ok {
		return ErrInvalidAlg
	}

	sigBytes := mustDecodeSig(jwt.Signature)

	if alg == "none" {
		if len(sigBytes) == 0 {
			return nil
		}
		return ErrInvalidSig
	}

	keyData := loadKey(key)

	switch alg {
	case "HS256":
		return verifyHMAC(jwt.signingInput, sigBytes, keyData, sha256.New)
	case "HS384":
		return verifyHMAC(jwt.signingInput, sigBytes, keyData, sha512.New384)
	case "HS512":
		return verifyHMAC(jwt.signingInput, sigBytes, keyData, sha512.New)
	default:
		return ErrUnsupportedAlg
	}
}

// Retrieves a signature key, either from a file if one exists
// with the specified name or if not, assumes that the value
// passed was the key and returns it
func loadKey(raw string) []byte {
	file, err := os.Stat(raw)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return []byte(raw)
	} else if err != nil {
		fatal(err)
	}
	if !file.Mode().IsRegular() {
		fatal(fmt.Errorf("invalid file type"))
	}
	data, err := os.ReadFile(raw)
	if err != nil {
		fatal(err)
	}
	return data
}

// Parses and returns a given public key and an error that is nil if successful
func parsePublicKey(keyData []byte) (any, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, ErrInvalidPEM
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}
	return pub, nil
}

// Verfies an HMAC signature using the specified hash func
func verifyHMAC(signingInput string, sig []byte, key []byte, hashFunc func() hash.Hash) error {
	mac := hmac.New(hashFunc, key)
	mac.Write([]byte(signingInput))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return ErrInvalidSig
	}
	return nil
}
