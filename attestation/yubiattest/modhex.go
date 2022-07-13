// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiattest

import (
	"crypto/x509"
	"fmt"
)

// ModHex extract serial number from attestation certificate
// and convert it to ModHex format.
// Ref: https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
func ModHex(cert *x509.Certificate) (modhex string, err error) {
	var serial []byte
	for _, ext := range cert.Extensions {
		// ext.Value contains the serial number encoded as a DER integer.
		//
		// The first byte denotes the type, namely integer,
		// but we already know that, so we do not use it.
		//
		// The second byte indicates the length of the actual data in bytes,
		// but we already have that information here (thanks to go library),
		// so we do not use it.
		//
		// Starting from the third byte is the actual data expressed in big-endian.
		if ext.Id.String() == "1.3.6.1.4.1.41482.3.7" {
			serial = ext.Value[2:]
		}
	}
	if serial == nil {
		return "", fmt.Errorf("cannot find serial number")
	}

	dst := make([]byte, 8)
	dstidx := 0

	switch len(serial) {
	// pad old serial number ModHex with two c (0)
	case 3:
		dst[0] = modHexMap[0]
		dst[1] = modHexMap[0]
		dstidx += 2
	case 4:
		break
	default:
		return "", fmt.Errorf("invalid serial number length: %v", len(serial))
	}

	for _, val := range serial {
		dst[dstidx] = modHexMap[(val>>4)&0xf]
		dst[dstidx+1] = modHexMap[val&0xf]
		dstidx += 2
	}
	return string(dst), nil
}
