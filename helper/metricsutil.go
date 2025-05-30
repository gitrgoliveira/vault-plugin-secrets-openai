// Package metricsutil provides minimal helpers for emitting Vault-compatible metrics.
// This is a local replacement for the missing Vault SDK metricsutil package.
package metricsutil

import (
	"context"

	"github.com/hashicorp/go-metrics"
)

// Label represents a key-value pair for metric labels.
type Label struct {
	Name  string
	Value string
}

// IncrCounterWithLabels increments a counter metric with the given name and labels.
// If go-metrics is not configured, this is a no-op.
func IncrCounterWithLabels(ctx context.Context, name string, labels []Label) {
	var mLabels []metrics.Label
	for _, l := range labels {
		mLabels = append(mLabels, metrics.Label{Name: l.Name, Value: l.Value})
	}
	metrics.IncrCounterWithLabels([]string{name}, 1, mLabels)
}
