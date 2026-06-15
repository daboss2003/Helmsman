package web

import (
	"encoding/json"
	"net/http"
)

// metricsHistoryLimit bounds one history response (the dashboard draws the recent
// window; older points are pruned by retention anyway).
const metricsHistoryLimit = 240

// metricPoint is one host sample for the dashboard charts. Bytes are sent raw and the
// client computes percentages, so the server stays a thin projection of host_metrics.
type metricPoint struct {
	T         int64   `json:"t"`
	CPU       float64 `json:"cpu"`
	Load1     float64 `json:"load1"`
	MemUsed   int64   `json:"memUsed"`
	MemTotal  int64   `json:"memTotal"`
	DiskUsed  int64   `json:"diskUsed"`
	DiskTotal int64   `json:"diskTotal"`
}

// handleMetricsHistory returns the recent host metric series as JSON for the live
// dashboard charts (read plane). It is a protected route (requireAuth) — cookie-
// authenticated, GET-only, same-origin — and reads ONLY the host_metrics ring, never
// per-container detail. Output is ordered oldest→newest so the client can append.
func (s *Server) handleMetricsHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	out := struct {
		Points []metricPoint `json:"points"`
	}{Points: []metricPoint{}}

	if s.db == nil {
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	// Newest N rows, then reversed to oldest→newest for the chart.
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT ts, cpu_pct, load1, mem_used, mem_total, disk_used, disk_total
		 FROM host_metrics ORDER BY ts DESC LIMIT ?`, metricsHistoryLimit)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var rev []metricPoint
	for rows.Next() {
		var p metricPoint
		if err := rows.Scan(&p.T, &p.CPU, &p.Load1, &p.MemUsed, &p.MemTotal, &p.DiskUsed, &p.DiskTotal); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		rev = append(rev, p)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Reverse into chronological order.
	out.Points = make([]metricPoint, 0, len(rev))
	for i := len(rev) - 1; i >= 0; i-- {
		out.Points = append(out.Points, rev[i])
	}
	_ = json.NewEncoder(w).Encode(out)
}
