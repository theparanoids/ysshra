package main

import (
	"context"
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"go.vzbuilders.com/peng/sshra-oss/agent/ssh"
	"go.vzbuilders.com/peng/sshra-oss/config"
	"go.vzbuilders.com/peng/sshra-oss/crypki"
	"go.vzbuilders.com/peng/sshra-oss/csr"
	"go.vzbuilders.com/peng/sshra-oss/gensign"
	"go.vzbuilders.com/peng/sshra-oss/gensign/regular"
)

const (
	// TODO: specify a config path.
	confPath = ""
	logFile  = "/var/log/sshra/gensign.log"
)

var handlerCreators = map[string]gensign.CreateHandler{
	regular.HandlerName: regular.NewHandler,
}

func main() {
	log.Logger = log.Logger.With().Caller().Str("app", "gensign").Logger()
	zerolog.MessageFieldName = "msg"
	zerolog.ErrorFieldName = "err"

	file, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0664)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create log file")
	}
	defer file.Close()
	log.Logger = log.Logger.Output(io.MultiWriter(file, os.Stderr))

	conf, err := config.NewGensignConfig(confPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load configuration")
	}

	reqParam, err := csr.NewReqParam(os.Getenv, func() []string {
		return os.Args
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create request parameter")
	}
	log.Logger = log.Logger.With().Str("id", reqParam.TransID).Logger()

	conn, err := ssh.AgentConn()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize the connection for ssh agent")
	}
	defer conn.Close()

	var handlers []gensign.Handler
	// Create Handler by the configuration.
	for hName := range conf.HandlerConfig {
		// Lookup creator by the handler mapping.
		create, ok := handlerCreators[hName]
		if !ok {
			log.Warn().Msgf("cannot find creator for handler %s", hName)
			continue
		}
		handler, err := create(conf, conn)
		if err != nil {
			log.Warn().Msgf("cannot create handler %s", hName)
			continue
		}
		handlers = append(handlers, handler)
	}

	signer, err := crypki.NewSignerWithGensignConf(*conf)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create signer")
	}

	ctx, cancel := context.WithTimeout(context.Background(), conf.RequestTimeout)
	defer cancel()
	if err := gensign.Run(ctx, reqParam, handlers, signer); err != nil {
		if gensign.IsErrorOfType(err, gensign.Panic) {
			// gensign will return debug stack in err when panic.
			// We do not want it to be printed to os.Stderr since it will also go to user's console.
			log.Logger = log.Output(file)
		}
		log.Fatal().Err(err).Msg("failed to run gensign")

	}
}
