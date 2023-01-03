// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package yubiagent

//go:generate mockgen -destination=./mock_shimagent_test.go -package=yubiagent github.com/theparanoids/ysshra/agent/shimagent ShimAgent
//go:generate mockgen -destination=./mock_yubiagent_test.go -package=yubiagent github.com/theparanoids/ysshra/agent/yubiagent YubiAgent

// #######################################################
// Following commands generates testdata for client_test.go.

//go:generate rm -rf ./out

// Generate root CA credentials.
//go:generate certstrap init --passphrase "" --common-name "Unittest Root CA" --years 80
//go:generate certstrap request-cert --passphrase "" --common-name "Unittest Attestation f9"

// Generate f9 credentials for 1st yubikey.
//go:generate certstrap sign Unittest_Attestation_f9 --passphrase "" --CA Unittest_Root_CA --years 80 --intermediate

// Generate 9a (self-signed) cert and attest-cert.
//go:generate certstrap init --passphrase "" --common-name "Unittest Authentication 9a"
//go:generate certstrap request-cert --passphrase "" --common-name "Unittest Authentication 9a attest" --key ./out/Unittest_Authentication_9a.key
//go:generate certstrap sign Unittest_Authentication_9a_attest --passphrase "" --CA Unittest_Attestation_f9 --years 80 --cert ./out/Unittest_Authentication_9a_attest.crt

// Generate 9e (self-signed) cert and attest-cert.
//go:generate certstrap init --passphrase "" --common-name "Unittest Authentication 9e"
//go:generate certstrap request-cert --passphrase "" --common-name "Unittest Authentication 9e attest" --key ./out/Unittest_Authentication_9e.key
//go:generate certstrap sign Unittest_Authentication_9e_attest --passphrase "" --CA Unittest_Attestation_f9 --years 80 --cert ./out/Unittest_Authentication_9e_attest.crt

//go:generate mkdir -p ./testdata
//go:generate bash -c "mv ./out/*.crt ./testdata/"

//go:generate rm -rf ./out
