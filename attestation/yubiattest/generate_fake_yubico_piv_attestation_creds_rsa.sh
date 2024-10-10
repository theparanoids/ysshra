#!/bin/bash
# Copyright 2022 Yahoo Inc.
# Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

set -euo pipefail

CA_CERT=$1
CA_KEY=$2

pushd ./out

# Generate a key pair
openssl genrsa -out fake_yubico_piv_attestation.key 2048 > /dev/null 2>&1

# Certificate signing request configuration
echo "# Configuration for generating the certificate signing request
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
CN=Fake Yubico PIV Attestation" > fake_yubico_piv_attestation_csr.rsa.conf


# Create the certificate signing request
openssl req -new -sha256 \
  -key fake_yubico_piv_attestation.key \
  -config fake_yubico_piv_attestation_csr.rsa.conf \
  -out fake_yubico_piv_attestation.csr

# "1.3.6.1.4.1.41482.3.3" indicates the yubikey firmware version.
# "DER:04:03:05" is the DER encoding of 4.3.5.
# "cfcecdcb" is the ModHex encoding of 04:03:05.
# Ref: https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
echo "1.3.6.1.4.1.41482.3.3=DER:04:03:05" > fake_yubico_piv_attestation_extensions.rsa.conf

# "1.3.6.1.4.1.41482.3.7" indicates the serial number of the yubikey.
# "DER:02:04:04:03:02:01" is the DER encoding of the number.
# The first byte (`02`) indicates that the type is integer.
# The second byte (`04`) denotes the number of bytes of the value.
# Ref:
# - https://en.wikipedia.org/wiki/X.690#Encoding_structure
# - https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-integer
# Reference: https://developers.yubico.com/OTP/Modhex_Converter.html
echo "1.3.6.1.4.1.41482.3.7=DER:02:04:04:03:02:01" >> fake_yubico_piv_attestation_extensions.rsa.conf

# Fake Yubico PIV CA signs the certificate
openssl x509 -req -sha256 -CAcreateserial \
  -days 3650 \
  -in fake_yubico_piv_attestation.csr \
  -CA "${CA_CERT}" \
  -CAkey "${CA_KEY}" \
  -extfile fake_yubico_piv_attestation_extensions.rsa.conf \
  -out fake_yubico_piv_attestation.rsa.crt > /dev/null 2>&1
