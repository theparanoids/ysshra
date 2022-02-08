package gensign

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"

	"go.vzbuilders.com/peng/sshra-oss/csr"
)

const timeout = 60 * time.Second

func Run(params *csr.ReqParam, handlers []Handler, signer csr.Signer) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
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
		// TODO: [SSHCA-2740] add a function to Handler to return the handler name, so that we can identify which handler failed.
		log.Info().Err(err).Msg("handler authentication failed")
	}
	if handler == nil {
		return errors.New("all authentications failed")
	}

	csrAgentKeys, err := handler.Generate(params)
	if err != nil {
		return fmt.Errorf(`failed to generate CSR: %v`, err)
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
	log.Info().Stringer("elapsed", time.Since(start)).Msg("gensign success")
	return nil
}
