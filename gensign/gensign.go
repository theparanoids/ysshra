// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package gensign

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog/log"
	"go.vzbuilders.com/peng/sshra-oss/csr"
	"go.vzbuilders.com/peng/sshra-oss/internal/logkey"
	"golang.org/x/crypto/ssh"
)

func Run(ctx context.Context, params *csr.ReqParam, handlers []Handler, signer csr.Signer) (err error) {
	// Prepare for panic logs
	defer func() {
		if r := recover(); r != nil {
			err = NewError(Panic, "", fmt.Errorf(`unexpected crash: %q`, string(debug.Stack())))
		}
	}()

	start := time.Now()

	var handler Handler
	for _, h := range handlers {
		err := h.Authenticate(params)
		if err == nil {
			handler = h
			break
		}
		log.Info().Err(err).Str("handler", h.Name()).Msgf("authentication failed")
	}
	if handler == nil {
		return errors.New("all authentications failed")
	}

	csrAgentKeys, err := handler.Generate(params)
	if err != nil {
		return fmt.Errorf(`failed to generate CSR: %v`, err)
	}

	if len(csrAgentKeys) == 0 {
		return fmt.Errorf(`no csr generated: %v`, err)
	}

	for _, agentKey := range csrAgentKeys {
		var (
			certs    []ssh.PublicKey
			comments []string
		)
		for _, csr := range agentKey.CSRs() {
			cert, comment, err := signer.Sign(ctx, csr)
			if err != nil {
				return fmt.Errorf("failed to sign CSR: %v", err)
			}
			certs = append(certs, cert...)
			comments = append(comments, comment...)
		}
		err = agentKey.AddCertsToAgent(certs, comments)
		if err != nil {
			return fmt.Errorf("failed to add certificates into the agent: %v", err)
		}
	}
	log.Info().Stringer(logkey.TimeElapseField, time.Since(start)).
		Str(logkey.TransIDField, params.TransID).
		Str(logkey.HandlerField, handler.Name()).
		Msgf("gensign success")
	return nil
}
