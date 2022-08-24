// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package utils

// #######################################################
// Following commands generates testdata for parse_test.go.

//go:generate rm -rf ./out

// Generate root CA credentials.
//go:generate certstrap init --passphrase "" --common-name "Unittest Root CA" --years 80
//go:generate certstrap request-cert --passphrase "" --common-name "Unittest PEM"

// Generate a valid pem file with 2 certs.
//go:generate certstrap sign Unittest_PEM --passphrase "" --CA Unittest_Root_CA --years 80 --cert ./out/pem.cert1
//go:generate certstrap sign Unittest_PEM --passphrase "" --CA Unittest_Root_CA --years 80 --cert ./out/pem.cert2
//go:generate bash -c "cat ./out/pem.cert1 ./out/pem.cert2 > ./out/pem.cert"

// Generate a broken pem cert.
//go:generate bash -c "head -c 50 ./out/pem.cert > ./out/pemBROKEN.cert"

//go:generate mkdir -p ./testdata
//go:generate bash -c "mv ./out/*.cert ./testdata/"

//go:generate rm -rf ./out
