// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiattest

import (
	"crypto"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"math/big"
)

var hashPrefixes1 = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

// There are multiple ways to represent the prefix for each hash algorithm. This structure contains the second version.
var hashPrefixes2 = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x1e, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x1f, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2b, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x3f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {}, // Only one representation?
}

// checkSignature verifies that signature is a valid signature over signed from
// a crypto.PublicKey, allowing missing null signatures.
// This function exists because we cannot verify the attestation certificates using native libraries
// due to a flaw in library crypto.
// Ref: https://github.com/golang/go/issues/16683
func checkSignature(algo x509.SignatureAlgorithm, signed, signature []byte, publicKey crypto.PublicKey) (err error) {
	var hashType crypto.Hash

	switch algo {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		hashType = crypto.SHA1
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256:
		hashType = crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		hashType = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		hashType = crypto.SHA512
	case x509.MD2WithRSA, x509.MD5WithRSA:
		return x509.InsecureAlgorithmError(algo)
	default:
		return x509.ErrUnsupportedAlgorithm
	}

	if !hashType.Available() {
		return x509.ErrUnsupportedAlgorithm
	}
	h := hashType.New()

	h.Write(signed)
	digest := h.Sum(nil)

	switch pub := publicKey.(type) {
	// We only need check YubiKey certificates, so *rsa.PublicKey is enough.
	// Ref: https://docs.yubico.com/yesdk/users-manual/application-piv/slots.html
	case *rsa.PublicKey:
		return verifyPKCS1v15(pub, hashType, digest, signature)
	}
	return x509.ErrUnsupportedAlgorithm
}

func verifyPKCS1v15(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error {
	hashLen, prefix1, prefix2, err := pkcs1v15HashInfo(hash, len(hashed))
	if err != nil {
		return err
	}

	tLen1 := len(prefix1) + hashLen
	tLen2 := len(prefix2) + hashLen
	k := (pub.N.BitLen() + 7) / 8
	if k < tLen1+11 {
		return rsa.ErrVerification
	}

	c := new(big.Int).SetBytes(sig)
	m := encrypt(new(big.Int), pub, c)
	em := leftPad(m.Bytes(), k)
	// EM = 0x00 || 0x01 || PS || 0x00 || T

	ok := subtle.ConstantTimeByteEq(em[0], 0)
	ok &= subtle.ConstantTimeByteEq(em[1], 1)
	ok &= subtle.ConstantTimeCompare(em[k-hashLen:k], hashed)
	prefix1ok := subtle.ConstantTimeCompare(em[k-tLen1:k-hashLen], prefix1)
	prefix2ok := subtle.ConstantTimeCompare(em[k-tLen2:k-hashLen], prefix2)
	prefix1ok &= subtle.ConstantTimeByteEq(em[k-tLen1-1], 0)
	prefix2ok &= subtle.ConstantTimeByteEq(em[k-tLen2-1], 0)
	ok &= (prefix1ok | prefix2ok)

	var correctTLen int
	switch {
	case prefix1ok == 1:
		correctTLen = tLen1
	case prefix2ok == 1:
		correctTLen = tLen2
	}
	for i := 2; i < k-correctTLen-1; i++ {
		ok &= subtle.ConstantTimeByteEq(em[i], 0xff)
	}

	if ok != 1 {
		return rsa.ErrVerification
	}

	return nil
}

func pkcs1v15HashInfo(hash crypto.Hash, inLen int) (hashLen int, prefix1 []byte, prefix2 []byte, err error) {
	// Special case: crypto.Hash(0) is used to indicate that the data is signed directly.
	if hash == 0 {
		return inLen, nil, nil, nil
	}
	hashLen = hash.Size()
	if inLen != hashLen {
		return 0, nil, nil, errors.New("crypto/rsa: input must be hashed message")
	}
	prefix1, ok := hashPrefixes1[hash]
	if !ok {
		return 0, nil, nil, errors.New("crypto/rsa: unsupported hash function")
	}
	prefix2, ok = hashPrefixes2[hash]
	if !ok {
		return 0, nil, nil, errors.New("crypto/rsa: unsupported hash function")
	}
	return
}

func encrypt(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}

func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}
