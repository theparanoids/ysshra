package main

import (
	"log"
	"os"

	"go.vzbuilders.com/peng/sshra-oss/agent/ssh"
	"go.vzbuilders.com/peng/sshra-oss/config"
	"go.vzbuilders.com/peng/sshra-oss/csr"
	"go.vzbuilders.com/peng/sshra-oss/gensign"
	"go.vzbuilders.com/peng/sshra-oss/gensign/regular"
	"go.vzbuilders.com/peng/sshra-oss/internal/cert/signer"
)

// TODO: specify a config path.
const confPath = ""

var handlerCreators = map[string]gensign.CreateHandler{
	regular.HandlerName: regular.NewHandler,
}

func main() {
	conf, err := config.NewGensignConfig(confPath)
	if err != nil {
		log.Fatalf("failed to load gensign configuration, %v", err)
	}
	// TODO: Setup mutli-writer for info and debug loggers.

	conn, err := ssh.AgentConn()
	if err != nil {
		log.Fatalf("failed to initailize the connection for ssh agent, %v", err)
	}

	var handlers []gensign.Handler
	// Create Handler by the configuration.
	for hName, _ := range conf.HandlerConfig {
		// Lookup creator by the handler mapping.
		create, ok := handlerCreators[hName]
		if !ok {
			log.Printf("warning: %v", err)
			continue
		}
		handler, err := create(conf, conn)
		if err != nil {
			log.Printf("warning: %v", err)
			continue
		}
		handlers = append(handlers, handler)
	}

	reqParam, err := csr.NewReqParam(os.Getenv, func() []string {
		return os.Args
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := gensign.Run(reqParam, handlers, signer.NewCrypkiSigner(conf)); err != nil {
		log.Fatal(err)
	}
}
