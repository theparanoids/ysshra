// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiattest

// generate_test.go generates credentials for unit tests.
//go:generate rm -rf ./out

// #######################################################
// Following commands generates testdata for attest_test.go.

// Generate root CA credentials.
//go:generate certstrap init --passphrase "" --common-name "Unittest Root CA" --years 80
//go:generate certstrap request-cert --passphrase "" --common-name "Unittest Attestation f9"

// Generate f9 credentials for 1st yubikey.
//go:generate certstrap sign Unittest_Attestation_f9 --passphrase "" --CA Unittest_Root_CA --years 80 --intermediate

// Generate 9a (self-signed) cert and attest-cert for 1st yubikey.
//go:generate certstrap init --passphrase "" --common-name "Unittest Authentication 9a"
//go:generate certstrap request-cert --passphrase "" --common-name "Unittest Authentication 9a attest" --key ./out/Unittest_Authentication_9a.key
//go:generate certstrap sign Unittest_Authentication_9a_attest --passphrase "" --CA Unittest_Attestation_f9 --years 80 --cert ./out/Unittest_Authentication_9a_attest.crt

// Generate f9 credentials for 2nd yubikey.
//go:generate certstrap request-cert --passphrase "" --common-name "Unittest Attestation f9 2"
//go:generate certstrap sign Unittest_Attestation_f9_2 --passphrase "" --CA Unittest_Root_CA --years 80 --intermediate

// Generate 9a (self-signed) cert and attest-cert for 2nd yubikey.
//go:generate certstrap init --passphrase "" --common-name "Unittest Authentication 9a 2"
//go:generate certstrap request-cert --passphrase "" --common-name "Unittest Authentication 9a attest 2" --key ./out/Unittest_Authentication_9a_2.key
//go:generate certstrap sign Unittest_Authentication_9a_attest_2 --passphrase "" --CA Unittest_Attestation_f9_2 --years 80 --cert ./out/Unittest_Authentication_9a_attest_2.crt

// #######################################################
// Following commands generates testdata for modhex_test.go and signature_test.go

// Generate root CA credentials.
//go:generate certstrap init --passphrase "" --common-name "fake Yubico PIV Root CA" --years 80
//go:generate ./generate_fake_yubico_piv_attestation_creds.sh ./Fake_Yubico_PIV_Root_CA.crt ./Fake_Yubico_PIV_Root_CA.key

// Move required credentials to ./testdata.
//go:generate mkdir -p ./testdata
//go:generate bash -c "mv ./out/*.crt ./testdata/"

//go:generate rm -rf ./out
