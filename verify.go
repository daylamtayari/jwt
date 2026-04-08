package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"os"
)

var (
	ErrInvalidAlg     = errors.New("invalid alg claim")
	ErrInvalidKey     = errors.New("invalid key format")
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
	case "RS256":
		return verifyRSA(jwt.signingInput, sigBytes, keyData, crypto.SHA256)
	case "RS384":
		return verifyRSA(jwt.signingInput, sigBytes, keyData, crypto.SHA384)
	case "RS512":
		return verifyRSA(jwt.signingInput, sigBytes, keyData, crypto.SHA512)
	case "PS256":
		return verifyRSAPSS(jwt.signingInput, sigBytes, keyData, crypto.SHA256)
	case "PS384":
		return verifyRSAPSS(jwt.signingInput, sigBytes, keyData, crypto.SHA384)
	case "PS512":
		return verifyRSAPSS(jwt.signingInput, sigBytes, keyData, crypto.SHA512)
	case "ES256":
		return verifyECDSA(jwt.signingInput, sigBytes, keyData, crypto.SHA256, elliptic.P256())
	case "ES384":
		return verifyECDSA(jwt.signingInput, sigBytes, keyData, crypto.SHA384, elliptic.P384())
	case "ES512":
		return verifyECDSA(jwt.signingInput, sigBytes, keyData, crypto.SHA512, elliptic.P521())
	case "EdDSA":
		return verifyEdDSA(jwt.signingInput, sigBytes, keyData)
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
func verifyHMAC(signingInput, sig, key []byte, hashFunc func() hash.Hash) error {
	mac := hmac.New(hashFunc, key)
	mac.Write(signingInput)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return ErrInvalidSig
	}
	return nil
}

// Verifies an RSA PKCS signature
func verifyRSA(signingInput, sig, keyData []byte, hash crypto.Hash) error {
	key, err := parsePublicKey(keyData)
	if err != nil {
		return err
	}

	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return ErrInvalidKey
	}

	h := hash.New()
	h.Write(signingInput)
	return rsa.VerifyPKCS1v15(pub, hash, h.Sum(nil), sig)
}

// Verifies an RSA PSS signature
func verifyRSAPSS(signingInput, sig, keyData []byte, hash crypto.Hash) error {
	key, err := parsePublicKey(keyData)
	if err != nil {
		return err
	}

	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return ErrInvalidKey
	}

	h := hash.New()
	h.Write(signingInput)
	return rsa.VerifyPSS(pub, hash, h.Sum(nil), sig, nil)
}

// Verifies an ECDSA signature
func verifyECDSA(signingInput, sig, keyData []byte, hash crypto.Hash, curve elliptic.Curve) error {
	key, err := parsePublicKey(keyData)
	if err != nil {
		return err
	}

	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return ErrInvalidKey
	}

	keySize := (curve.Params().BitSize + 7) / 8
	if len(sig) != 2*keySize {
		return ErrInvalidSig
	}

	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])
	h := hash.New()
	h.Write(signingInput)
	if !ecdsa.Verify(pub, h.Sum(nil), r, s) {
		return ErrInvalidSig
	}
	return nil
}

// Verifies an Ed25519 signature
func verifyEdDSA(signingInput, sig, keyData []byte) error {
	key, err := parsePublicKey(keyData)
	if err != nil {
		return err
	}

	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return ErrInvalidKey
	}
	if !ed25519.Verify(pub, signingInput, sig) {
		return ErrInvalidSig
	}
	return nil
}
