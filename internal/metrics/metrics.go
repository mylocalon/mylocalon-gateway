// Package metrics is the MVP metrics stub (OBSERVABILITY.md §5–6): atomic
// counters rendered in Prometheus text format. Swap for a real registry later
// without touching call sites.
package metrics

import (
	"fmt"
	"io"
	"sync/atomic"
)

type Metrics struct {
	ActiveTunnels  atomic.Int64
	RequestsTotal  atomic.Int64
	TunnelConnects atomic.Int64
	UpstreamErrors atomic.Int64
	durationSumMs  atomic.Int64
	durationCount  atomic.Int64
}

func New() *Metrics { return &Metrics{} }

func (m *Metrics) ObserveDuration(ms int64) {
	m.durationSumMs.Add(ms)
	m.durationCount.Add(1)
}

func (m *Metrics) WritePrometheus(w io.Writer) {
	fmt.Fprintf(w, "# TYPE mylocalon_active_tunnels gauge\nmylocalon_active_tunnels %d\n", m.ActiveTunnels.Load())
	fmt.Fprintf(w, "# TYPE mylocalon_requests_total counter\nmylocalon_requests_total %d\n", m.RequestsTotal.Load())
	fmt.Fprintf(w, "# TYPE mylocalon_tunnel_connects_total counter\nmylocalon_tunnel_connects_total %d\n", m.TunnelConnects.Load())
	fmt.Fprintf(w, "# TYPE mylocalon_upstream_errors_total counter\nmylocalon_upstream_errors_total %d\n", m.UpstreamErrors.Load())
	fmt.Fprintf(w, "# TYPE mylocalon_request_duration_ms summary\nmylocalon_request_duration_ms_sum %d\nmylocalon_request_duration_ms_count %d\n",
		m.durationSumMs.Load(), m.durationCount.Load())
}
