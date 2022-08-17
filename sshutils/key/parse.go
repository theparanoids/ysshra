// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package key

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// GetPrivateKeyFromFile reads the private key from
// file and returns *rsa.PrivateKey, *dsa.PrivateKey
// or *ecdsa.PrivateKeyrsa; otherwise, an error is returned.
func GetPrivateKeyFromFile(file string) (interface{}, error) {
	if err := validateKeyFile(file); err != nil {
		return nil, err
	}
	buffer, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParseRawPrivateKey(buffer)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GetPublicKeysFromBytes returns a slice of SSH public keys from the given data chunk.
func GetPublicKeysFromBytes(data []byte) (keys []ssh.PublicKey, comments []string, err error) {
	var key ssh.PublicKey
	var comment string
	for len(data) > 0 {
		key, comment, _, data, err = ssh.ParseAuthorizedKey(data)
		if key != nil {
			keys = append(keys, key)
			comments = append(comments, comment)
		}
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("keys not found, got err: %v", err)
	}
	return keys, comments, nil
}

// GetPublicKeyFromFile returns the first SSH public key from the given file; otherwise, an error is returned.
func GetPublicKeyFromFile(file string) (key ssh.PublicKey, comment string, err error) {
	keys, comments, err := GetPublicKeysFromFile(file)
	if err != nil {
		return nil, "", err
	}
	if len(keys) == 0 {
		return nil, "", errors.New("keys not found")
	}
	if len(comments) == 0 {
		return keys[0], "", nil
	}
	return keys[0], comments[0], nil
}

// GetPublicKeysFromFile returns a slice of SSH public keys from the given file; otherwise, an error is returned.
func GetPublicKeysFromFile(file string) (keys []ssh.PublicKey, comments []string, err error) {
	if err := validateKeyFile(file); err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}
	return GetPublicKeysFromBytes(data)
}

// CastSSHPublicKeyToAgentKey casts any types of SSH PublicKey to *agent.Key.
func CastSSHPublicKeyToAgentKey(key ssh.PublicKey) *agent.Key {
	if _, ok := key.(*agent.Key); ok {
		return key.(*agent.Key)
	}

	result := new(agent.Key)
	result.Format = key.Type()
	result.Blob = key.Marshal()
	return result
}

// CastSSHPublicKeyToCertificate casts any types of SSH PublicKey to *ssh.Certificate; otherwise, an error is returned.
func CastSSHPublicKeyToCertificate(key ssh.PublicKey) (*ssh.Certificate, error) {
	if !strings.Contains(key.Type(), "cert") {
		return nil, fmt.Errorf("the key type is not cert")
	}

	if _, ok := key.(*ssh.Certificate); ok {
		return key.(*ssh.Certificate), nil
	}

	pub, err := ssh.ParsePublicKey(key.Marshal())
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key, err: %v", err)
	}
	return pub.(*ssh.Certificate), nil
}
