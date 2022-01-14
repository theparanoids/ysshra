package gensign

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"time"

	"go.vzbuilders.com/peng/sshra-oss/csr"
	"golang.org/x/crypto/ssh"
)

const timeout = 60 * time.Second

func Run(params *csr.ReqParam, handlers []Handler, signer csr.Signer) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Prepare for panic logs
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf(`gensign: id=%q, msg="unexpected crash", err=%q`, params.TransID, string(debug.Stack()))
		}
	}()

	// Emit log message for start.
	start := time.Now()
	log.Printf(`gensign: id=%q, msg="validating input"`, params.TransID)

	var handler Handler
	for _, h := range handlers {
		if err := h.Authenticate(params); err == nil {
			handler = h
			break
		}
		// TODO: Log error to some debug file here.
		//
		// Note that there will be many false positives
		// because only one handler is expected to authenticate the user successfully,
		// and that's why we want this information to be in a debug file instead of a regular log file.
	}
	if handler == nil {
		return fmt.Errorf(`gensign: id=%q, msg="all authentications failed"`, params.TransID)
	}

	csrAgentKeys, err := handler.Generate(params)
	if err != nil {
		return fmt.Errorf(`gensign: id=%q, msg="failed to generate CSR", err=%q`, params.TransID, err)
	}

	for _, agentKey := range csrAgentKeys {
		var (
			certs    []ssh.PublicKey
			comments []string
		)
		for _, csr := range agentKey.CSRs() {
			cert, comment, err := signer.Sign(ctx, csr)
			if err != nil {
				return fmt.Errorf(`gensign: id=%q, msg="failed to sign CSR", err=%q"`, params.TransID, err)
			}
			certs = append(certs, cert...)
			comments = append(comments, comment...)
		}
		err = agentKey.AddCertsToAgent(certs, comments)
		if err != nil {
			return fmt.Errorf(`gensign: id=%q, msg="failed to add certificates into the agent", err=%q`, params.TransID, err)
		}
	}
	log.Printf(`gensign: id=%q, msg="gensign success", elapsed=%q`, params.TransID, time.Since(start).String())
	return nil
}
