// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

// Package message provides functionality for handling message that a client pass to an RA.
// The message contain attributes of SSH certificate that the client requests for.
// For example:
// "IFVer=6 SSHClientVersion=8.1 req=alice@host1 HardKey=true Touch2SSH=true github=false"
// means the requester is "alice" in host "host1", the certificate she requests has the corresponding private key in YubiKey,
// she needs to touch the YubiKey before login, and the certificate is not for GitHub.
// In particular, this package provides marshaling and unmarshaling between the standard message struct and its string format.
package message
