package monitor

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/hostmon"
	"github.com/daboss2003/mooring/internal/store"
)

func fakeEngine(t *testing.T) *docker.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"26.1.0"}`))
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"Id":"abc","Names":["/shop-web-1"],"Image":"nginx","State":"running","Status":"Up (healthy)",
			 "Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"web"}},
			{"Id":"def","Names":["/shop-db-1"],"Image":"postgres","State":"exited","Status":"Exited (0)",
			 "Labels":{"com.docker.compose.project":"shop","com.docker.compose.service":"db"}},
			{"Id":"xyz","Names":["/loose"],"Image":"redis","State":"running","Status":"Up","Labels":{}}
		]`))
	})
	mux.HandleFunc("/containers/abc/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Id":"abc","RestartCount":1,"State":{"Status":"running","Running":true,"Health":{"Status":"healthy"}}}`))
	})
	mux.HandleFunc("/containers/def/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Id":"def","RestartCount":5,"State":{"Status":"exited","Running":false}}`))
	})
	mux.HandleFunc("/containers/abc/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"cpu_stats":{"cpu_usage":{"total_usage":2000},"system_cpu_usage":100000,"online_cpus":2},
			"precpu_stats":{},"memory_stats":{"usage":1048576,"limit":2097152,"stats":{}}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return docker.New(strings.TrimPrefix(srv.URL, "http://"))
}

func newTestMonitor(t *testing.T) (*Monitor, *store.DB) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := New(db, fakeEngine(t), hostmon.New("/"), time.Second, time.Hour, log, nil)
	return m, db
}

func TestPollDiscoversAppsAndPersists(t *testing.T) {
	m, db := newTestMonitor(t)
	snap := m.pollOnce(context.Background())

	if !snap.DockerOK {
		t.Fatalf("docker not OK: %s", snap.DockerErr)
	}
	if len(snap.Apps) != 1 {
		t.Fatalf("want 1 app (unlabeled container excluded), got %d", len(snap.Apps))
	}
	app := snap.Apps[0]
	if app.Project != "shop" || app.Total() != 2 {
		t.Fatalf("app grouping wrong: %+v", app)
	}
	if app.UpCount() != 1 || !app.Degraded() { // db is exited → degraded
		t.Errorf("expected 1 up + degraded, got up=%d degraded=%v", app.UpCount(), app.Degraded())
	}
	// services sorted: db, web
	if app.Services[0].Service != "db" || app.Services[0].RestartCount != 5 {
		t.Errorf("db service wrong: %+v", app.Services[0])
	}
	if app.Services[1].Service != "web" || app.Services[1].Health != "healthy" {
		t.Errorf("web service wrong: %+v", app.Services[1])
	}

	// persisted: apps row + container_metrics rows
	var nApps, nMetrics int
	_ = db.QueryRow(`SELECT COUNT(*) FROM apps WHERE project='shop'`).Scan(&nApps)
	_ = db.QueryRow(`SELECT COUNT(*) FROM container_metrics WHERE project='shop'`).Scan(&nMetrics)
	if nApps != 1 {
		t.Errorf("apps rows = %d, want 1", nApps)
	}
	if nMetrics != 2 {
		t.Errorf("container_metrics rows = %d, want 2", nMetrics)
	}
}

func TestPollDockerDownIsGraceful(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// point at a dead address
	m := New(db, docker.New("127.0.0.1:1"), hostmon.New("/"), time.Second, time.Hour, log, nil)
	snap := m.pollOnce(context.Background())
	if snap.DockerOK {
		t.Error("expected DockerOK=false against a dead proxy")
	}
	if snap.DockerErr == "" {
		t.Error("expected a DockerErr message")
	}
}

func TestSnapshotAppByProject(t *testing.T) {
	s := &Snapshot{Apps: []App{{Project: "a"}, {Project: "b"}}}
	if s.AppByProject("b") == nil || s.AppByProject("c") != nil {
		t.Error("AppByProject lookup wrong")
	}
}
