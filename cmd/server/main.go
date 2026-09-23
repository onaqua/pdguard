// Command server runs pdguard: an HTTP proxy that masks personal data in a
// payload on the way to an LLM and restores it on the way back.
//
// It wires the packages together and owns the process lifecycle — flags,
// environment, listener, signals, drain — and nothing else. Every decision
// about what to answer lives in internal/httpapi and internal/engine.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"pdguard/internal/config"
	"pdguard/internal/engine"
	"pdguard/internal/httpapi"
	"pdguard/internal/llm"
	"pdguard/internal/logging"
	"pdguard/internal/metrics"
	"pdguard/internal/pd/detect"
	"pdguard/internal/pd/dict"
	"pdguard/internal/pd/mask"
	"pdguard/internal/store"
)

// version is stamped at build time:
//
//	go build -ldflags "-X main.version=v1.0.0 -X pdguard/internal/metrics.Version=v1.0.0" ./cmd/server
//
// It is a plain var rather than a const precisely so -X can reach it.
var version = "dev"

// drainTimeout bounds the graceful shutdown. It is a little above the
// specification's 10-second request timeout, so a request that is still allowed
// to be in flight gets to finish instead of being cut off at the socket.
const drainTimeout = 12 * time.Second

// defaultConfigPath is where the shipped configuration lives. A missing file is
// not fatal — config.Load falls back to working defaults — so the service also
// starts from an empty image.
const defaultConfigPath = "configs/config.json"

func main() {
	if err := run(); err != nil {
		// The logger is configured by then in every path that can fail after
		// start-up; before that, stderr is all there is.
		logging.L().Error("fatal", "err", err.Error())
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", "", "path to the configuration file (default "+defaultConfigPath+", env PDGUARD_CONFIG)")
		addr        = flag.String("addr", "", "listen address, overrides the configuration (env PDGUARD_ADDR)")
		logLevel    = flag.String("log-level", "", "debug|info|warn|error, overrides the configuration (env PDGUARD_LOG_LEVEL)")
		logFormat   = flag.String("log-format", "", "json|text, overrides the configuration (env PDGUARD_LOG_FORMAT)")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	cfgPath := firstNonEmpty(*configPath, os.Getenv("PDGUARD_CONFIG"), defaultConfigPath)
	mgr, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	cfg := mgr.Get()

	level := firstNonEmpty(*logLevel, os.Getenv("PDGUARD_LOG_LEVEL"), cfg.Log.Level)
	format := firstNonEmpty(*logFormat, os.Getenv("PDGUARD_LOG_FORMAT"), cfg.Log.Format)
	logging.Setup(level, format)
	logging.SetSampling(cfg.Log.SampleEvery)

	applyMemoryLimit()

	metrics.Version = version

	st := store.New(store.Config{
		Shards:        cfg.Store.Shards,
		TTL:           time.Duration(cfg.Store.TTLSeconds) * time.Second,
		MaxEntries:    cfg.Store.MaxEntries,
		MaxValueBytes: cfg.Store.MaxValueBytes,
		MaxBytes:      cfg.Store.MaxBytes,
	})
	defer st.Close()

	eng := engine.New(engine.Options{Cfg: mgr, Store: st})

	adminToken := os.Getenv("PDGUARD_ADMIN_TOKEN")

	// The LLM API key comes only from the environment, never from the
	// configuration file, so it cannot leak through /admin/config or a log.
	llmClient := llm.New(llm.Options{
		BaseURL: cfg.LLM.BaseURL,
		Model:   cfg.LLM.Model,
		Timeout: time.Duration(cfg.LLM.TimeoutMS) * time.Millisecond,
		Stream:  cfg.LLM.Stream,
		CAFile:  cfg.LLM.CAFile,
		APIKey:  os.Getenv("PDGUARD_LLM_API_KEY"),
	})

	api := httpapi.New(httpapi.Options{
		Engine:     eng,
		Cfg:        mgr,
		Store:      st,
		Version:    version,
		AdminToken: adminToken,
		LLM:        llmClient,
	})

	listenAddr := firstNonEmpty(*addr, os.Getenv("PDGUARD_ADDR"), cfg.Server.Addr, ":8080")

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: api.Handler(),
		// ReadHeaderTimeout is the one timeout that must never be zero: without
		// it a client can hold a connection open by sending headers one byte at
		// a time (Slowloris) and exhaust the accept path for free.
		ReadHeaderTimeout: headerTimeout(cfg.Server.ReadTimeout),
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		// Headers are never large here; capping them keeps a hostile client
		// from allocating a megabyte per connection.
		MaxHeaderBytes: 1 << 16,
		ErrorLog:       slog.NewLogLogger(logging.L().Handler(), slog.LevelWarn),
	}

	logStartup(listenAddr, cfgPath, mgr, adminToken)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	api.SetReady(true)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("listen on %s: %w", listenAddr, err)
		}
		return nil
	case <-ctx.Done():
	}

	// Drain in order: stop advertising readiness first so a load balancer stops
	// sending new work, then let the in-flight requests finish, then drop the
	// store. Closing the store earlier would strand a demasking request that is
	// still being served.
	logging.L().Info("shutdown signal received, draining", "timeout_s", int(drainTimeout.Seconds()))
	api.SetReady(false)

	shutCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		logging.L().Warn("graceful shutdown did not complete", "err", err.Error())
		_ = srv.Close()
	}
	<-errCh
	logging.L().Info("stopped")
	return nil
}

// logStartup records what this process is: the one line an operator reads when
// something is wrong. Dictionary sizes and registry counts are here because an
// empty dictionary or a missing detector registration produces a service that
// answers 200 to everything while masking nothing, and this is the only place
// that failure is visible.
func logStartup(addr, cfgPath string, mgr *config.Manager, adminToken string) {
	cfg := mgr.Get()
	dictStats := dict.Stats()
	total := 0
	for _, n := range dictStats {
		total += n
	}

	attrs := []any{
		"version", version,
		"addr", addr,
		"config", cfgPath,
		"config_loaded", mgr.Path() != "",
		"detectors", len(detect.Detectors()),
		"strategies", len(mask.StrategyNames()),
		"dict_entries", total,
		"dict", dictStats,
		"systems", len(cfg.Systems),
		"require_system", cfg.RequireSystem,
		"fail_open", cfg.Server.FailOpen,
		"max_concurrent", cfg.Server.MaxConcurrent,
		"process_timeout_ms", cfg.Server.ProcessTimeout.Milliseconds(),
		// GOMAXPROCS is deliberately left at whatever the runtime picked; on a
		// cgroup-limited container that is the host core count, which is the
		// number worth seeing in the log when the latency budget is missed.
		"gomaxprocs", runtime.GOMAXPROCS(0),
		"numcpu", runtime.NumCPU(),
	}
	logging.L().Info("pdguard starting", attrs...)

	if adminToken == "" && cfg.Server.AdminToken == "" {
		logging.L().Warn("admin endpoints are unauthenticated; set PDGUARD_ADMIN_TOKEN before exposing this port")
	}
}

// headerTimeout derives a header deadline from the read timeout. Headers arrive
// in one packet in practice, so a short slice of the read budget is plenty and
// leaves the rest for a 100k-token body.
func headerTimeout(read time.Duration) time.Duration {
	const fallback = 5 * time.Second
	if read <= 0 {
		return fallback
	}
	if read < fallback {
		return read
	}
	return fallback
}

// firstNonEmpty returns the first value that is not blank, which is how the
// flag/env/file precedence above is expressed without a chain of ifs.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// applyMemoryLimit gives the garbage collector the cgroup memory limit the
// container was started with.
//
// Go reads the cgroup CPU quota for GOMAXPROCS but not the memory limit: left
// alone it targets roughly twice the live heap and happily runs past a 1 GiB
// container cap, at which point the kernel kills the process. That is the worst
// outcome available here, because the whole payload_id -> original mapping
// lives in memory: every reverse step still owed an original would come back
// with the mask instead, and half the score goes with it. A soft limit makes
// the collector work harder instead of dying.
//
// GOMEMLIMIT in the environment always wins — the runtime has already applied
// it by the time this runs, and an operator who set it meant it.
func applyMemoryLimit() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	limit, ok := cgroupMemoryLimit()
	if !ok {
		return
	}
	// Leave headroom for the allocations the collector cannot move: goroutine
	// stacks, the runtime's own bookkeeping and the off-heap cost of the
	// in-flight request buffers. 80% is the usual figure for this.
	soft := limit / 100 * 80
	debug.SetMemoryLimit(soft)
	logging.L().Info("memory limit applied",
		slog.Int64("cgroup_bytes", limit), slog.Int64("gomemlimit_bytes", soft))
}

// cgroupMemoryLimit reads the container memory limit, trying cgroup v2 first
// and falling back to v1. It returns false when there is no limit, when the
// value is the "unlimited" sentinel, or when the process is not containerised.
func cgroupMemoryLimit() (int64, bool) {
	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",                   // cgroup v2
		"/sys/fs/cgroup/memory/memory.limit_in_bytes", // cgroup v1
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(raw))
		if s == "" || s == "max" {
			continue
		}
		n, err := strconv.ParseInt(s, 10, 64)
		// A v1 cgroup with no limit reports a number close to MaxInt64; anything
		// above a terabyte is that sentinel, not a real allowance.
		if err != nil || n <= 0 || n > 1<<40 {
			continue
		}
		return n, true
	}
	return 0, false
}
