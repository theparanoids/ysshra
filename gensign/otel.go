// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package gensign

import (
	"context"
	"log"

	"github.com/theparanoids/ysshra/csr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	scopeName     = "github.com/theparanoids/ysshra/gensign"
	ysshraPanic   = "ysshra.panic"
	ysshraGensign = "ysshra.gensign.run"
)

var meter metric.Meter

// InitOTelMeter initializes the oTel meter for ysshra.
func InitOTelMeter() {
	meter = otel.GetMeterProvider().Meter(scopeName)
}

// ExportPanicMetric exports a panic metric to the oTel meter.
func ExportPanicMetric(ctx context.Context, _ *csr.ReqParam, msg string) {
	var err error
	panicCounter, err := meter.Int64Counter(
		ysshraPanic,
		metric.WithUnit("1"),
		metric.WithDescription("Count the number of HTTP handler panic"),
	)
	if err != nil {
		log.Printf("Error creating metric for panic: %v\n", err)
	}
	// TODO: add transID to traces instead of metrics to avoid high cardinality.
	panicCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("panic.message", msg),
	))
}

// ExportGensignRunMetric exports a gensign run metric to the oTel meter.
func ExportGensignRunMetric(ctx context.Context, runErr error) {
	var err error
	gensignRunCounter, err := meter.Int64Counter(
		ysshraGensign,
		metric.WithUnit("1"),
		metric.WithDescription("Count the number of gensign runs"),
	)
	if err != nil {
		log.Printf("Error creating metric for gensign run: %v\n", err)
	}
	var attributes []attribute.KeyValue
	if runErr != nil {
		gensignErr, ok := IsError(runErr)
		if ok {
			attributes = append(attributes, attribute.Int("gensign.error.type", int(gensignErr.Type())))
		} else {
			attributes = append(attributes, attribute.Int("gensign.error.type", int(Unknown)))
		}
	}
	gensignRunCounter.Add(ctx, 1, metric.WithAttributes(attributes...))
}
