// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"golang.org/x/crypto/ssh"
)

// PublicKeyAlgo is used to specify public key algorithm for the key pair in ssh-agent.
type PublicKeyAlgo int

// List of supported public key algorithms.
const (
	RSA2048 PublicKeyAlgo = iota
	RSA4096
	ECDSAsecp256r1
	ECDSAsecp384r1
	ECDSAsecp521r1
	// ED25519 is not supported in yubico hardware keys currently.
	ED25519
)

// GenerateKeyPair returns a new pair of keys for the specified algorithm.
// Caller should cast the returned private key to one of
// *rsa.PrivateKey, *ecdsa.PrivateKey or *ed25519.PrivateKey
// depending on the specified input.
func GenerateKeyPair(pka PublicKeyAlgo) (crypto.PrivateKey, ssh.PublicKey, error) {
	// TODO: validate public key algorithm.
	return createKeyPair(pka)
}

func createKeyPair(pka PublicKeyAlgo) (crypto.PrivateKey, ssh.PublicKey, error) {
	var (
		pubkey interface{}
		priv   interface{}
		err    error
	)
	switch pka {
	case RSA4096:
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, err
		}
		pubkey = priv.(*rsa.PrivateKey).Public()
	case ECDSAsecp256r1:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pubkey = priv.(*ecdsa.PrivateKey).Public()
	case ECDSAsecp384r1:
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pubkey = priv.(*ecdsa.PrivateKey).Public()
	case ECDSAsecp521r1:
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pubkey = priv.(*ecdsa.PrivateKey).Public()
	case ED25519:
		_, privkey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		priv = &privkey
		pubkey = priv.(*ed25519.PrivateKey).Public()
	case RSA2048:
		fallthrough // default is RSA2048
	default:
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		pubkey = priv.(*rsa.PrivateKey).Public()
	}
	sshpub, err := ssh.NewPublicKey(pubkey)
	if err != nil {
		return nil, nil, err
	}
	return priv, sshpub, nil
}
