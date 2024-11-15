package otellib

import (
	"context"
	"log"

	"github.com/theparanoids/ysshra/csr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	scopeName   = "github.com/theparanoids/ysshra/otellib"
	ysshraPanic = "ysshra.panic"
)

var meter metric.Meter

// InitMeter initializes the oTel meter for ysshra.
func InitMeter() {
	meter = otel.GetMeterProvider().Meter(scopeName)
}

// ExportPanicMetric exports a panic metric to the oTel meter.
func ExportPanicMetric(ctx context.Context, param *csr.ReqParam, msg string) {
	var err error
	panicCounter, err := meter.Int64Counter(
		ysshraPanic,
		metric.WithUnit("1"),
		metric.WithDescription("Count the number of HTTP handler panic"),
	)
	if err != nil {
		log.Printf("Error creating metric for panic: %v\n", err)
	}
	panicCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("gensign.transid", param.TransID),
		attribute.String("panic.message", msg),
	))
}
