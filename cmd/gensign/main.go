// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package main

import (
	"context"
	"io"
	golog "log"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/theparanoids/crypki/otellib"
	"github.com/theparanoids/ysshra/agent/ssh"
	"github.com/theparanoids/ysshra/config"
	"github.com/theparanoids/ysshra/crypki"
	"github.com/theparanoids/ysshra/csr"
	"github.com/theparanoids/ysshra/gensign"
	"github.com/theparanoids/ysshra/gensign/regular"
	"github.com/theparanoids/ysshra/internal/logkey"
	ysshra_otellib "github.com/theparanoids/ysshra/otellib"
	"github.com/theparanoids/ysshra/tlsutils"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const (
	confPath = "/opt/ysshra/config.json"
	logFile  = "/var/log/ysshra/gensign.log"
)

var handlerCreators = map[string]gensign.CreateHandler{
	regular.HandlerName: regular.NewHandler,
}

func main() {
	log.Logger = log.Logger.With().Caller().Str("app", "gensign").Logger()
	zerolog.MessageFieldName = logkey.MsgField
	zerolog.ErrorFieldName = logkey.ErrField

	file, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0664)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create log file")
	}
	defer file.Close()
	log.Logger = log.Logger.Output(io.MultiWriter(file, os.Stderr))
	fileLogger := log.Output(file)

	// Ensure all the 3rd party libraries, e.g. oTel, wouldn't log to os.Stderr since it will also go to user's console.
	golog.SetOutput(file)

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
			log.Warn().Err(err).Msgf("cannot create handler %s", hName)
			continue
		}
		handlers = append(handlers, handler)
	}

	signer, err := crypki.NewSignerWithGensignConf(*conf)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create signer")
	}

	if conf.OTel.Enabled {
		otelResource, err := resource.Merge(
			resource.Default(),
			resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceNameKey.String("gensign")),
		)
		if err != nil {
			fileLogger.Warn().Err(err).Msg("failed to create oTel resource")
		}
		otelTLSConf, err := tlsutils.TLSClientConfiguration(conf.OTel.ClientCertPath, conf.OTel.ClientKeyPath,
			[]string{conf.OTel.CACertPath})
		if err != nil {
			fileLogger.Warn().Err(err).Msg("failed to create oTel TLS config")
		}
		shutdownProvider := otellib.InitOTelSDK(context.Background(),
			conf.OTel.OTELCollectorEndpoint, otelTLSConf, otelResource)

		defer func() {
			if err := shutdownProvider(context.Background()); err != nil {
				fileLogger.Warn().Err(err).Msg("failed to shut down oTel provider")
			}
		}()
		ysshra_otellib.InitMeter()
	}

	ctx, cancel := context.WithTimeout(context.Background(), conf.RequestTimeout)
	defer cancel()
	if err := gensign.Run(ctx, reqParam, handlers, signer); err != nil {
		if gensign.IsErrorOfType(err, gensign.Panic) {
			// gensign will return debug stack in err when panic.
			// We do not want it to be printed to os.Stderr since it will also go to user's console.
			log.Logger = fileLogger
		}
		log.Error().Str(logkey.TransIDField, reqParam.TransID).Err(err).Msg("failed to run gensign")
	}
}
