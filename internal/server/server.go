// Package server serves the embedded 3-panel Hybrid Web Workbench, hardened REST API, and SSE stream.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa/internal/aggregator"
	"github.com/luminariadev/raksa/internal/assistant"
	"github.com/luminariadev/raksa/internal/bridge"
	"github.com/luminariadev/raksa/internal/ext"
	"github.com/luminariadev/raksa/internal/mcphub"
	"github.com/luminariadev/raksa/internal/playbook"
	"github.com/luminariadev/raksa/internal/policy"
	"github.com/luminariadev/raksa/internal/remediate"
	"github.com/luminariadev/raksa/internal/report"
	"github.com/luminariadev/raksa/internal/runner"
	"github.com/luminariadev/raksa/internal/schema"
	"github.com/luminariadev/raksa/internal/store"
	"github.com/luminariadev/raksa/internal/webui"
	"gopkg.in/yaml.v3"
)

const (
	sessionCookieName = "raksa_session"
	strictCSP         = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)

// Config configures the embedded Layer 7 HTTP Workbench server.
type Config struct {
	ListenAddr  string
	Workspace   string
	FromReports string
	BinDir      string
	HistoryPath string
	SIEMURL     string
	SIEMToken   string
	Token       string
	NoAuth      bool
	Auth        ext.AuthProvider
	Resolver    runner.BinaryResolver
	Exec        runner.CommandRunner
	Remediate   remediate.Executor
}

// SSEEvent represents a server-sent live telemetry update.
type SSEEvent struct {
	Type      string `json:"type"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

// Server serves the embedded Web UI, REST APIs, and live SSE telemetry bus.
type Server struct {
	cfg      Config
	history  *store.Store
	auth     ext.AuthProvider
	mu       sync.RWMutex
	active   schema.SuiteReport
	subMu    sync.Mutex
	subs     map[chan SSEEvent]struct{}
	assetSub fs.FS
}

// New constructs a Server initialized with workspace config and baseline fixture or empty report.
func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.ListenAddr) == "" {
		cfg.ListenAddr = "127.0.0.1:8787"
	}
	if strings.TrimSpace(cfg.Workspace) == "" {
		cfg.Workspace = "."
	}
	if strings.TrimSpace(cfg.HistoryPath) == "" {
		cfg.HistoryPath = store.DefaultHistoryPath()
	}
	if !cfg.NoAuth && strings.TrimSpace(cfg.Token) == "" {
		tok, err := generateToken()
		if err != nil {
			return nil, fmt.Errorf("generate session token: %w", err)
		}
		cfg.Token = tok
	}
	authProvider := cfg.Auth
	if authProvider == nil {
		expected := cfg.Token
		if cfg.NoAuth {
			expected = ""
		}
		authProvider = ext.LocalAuthProvider{ExpectedToken: expected}
	}

	subFS, err := fs.Sub(webui.AssetsFS, "assets")
	if err != nil {
		return nil, fmt.Errorf("mount embedded webui assets: %w", err)
	}

	s := &Server{
		cfg:      cfg,
		history:  store.Open(cfg.HistoryPath),
		auth:     authProvider,
		subs:     make(map[chan SSEEvent]struct{}),
		assetSub: subFS,
	}

	if err := s.initActiveReport(); err != nil {
		return nil, err
	}
	return s, nil
}

// Token returns the configured operator session token (empty when NoAuth is true).
func (s *Server) Token() string {
	return s.cfg.Token
}

func (s *Server) initActiveReport() error {
	polCfg, _, err := policy.Discover(s.cfg.Workspace, "")
	if err != nil {
		polCfg = policy.DefaultConfig()
	}
	if s.cfg.SIEMURL == "" && polCfg.SIEM.Endpoint != "" {
		s.cfg.SIEMURL = polCfg.SIEM.Endpoint
	}
	if s.cfg.SIEMToken == "" && polCfg.SIEM.TokenEnv != "" {
		s.cfg.SIEMToken = os.Getenv(polCfg.SIEM.TokenEnv)
	}

	if strings.TrimSpace(s.cfg.FromReports) != "" {
		ups, err := aggregator.LoadReportsFromPath(s.cfg.FromReports)
		if err != nil {
			return err
		}
		s.active = aggregator.Merge(ups, nil, aggregator.MergeOptions{
			Profile: "aggregated",
			Target:  s.cfg.FromReports,
			Policy:  polCfg,
			Now:     time.Now().UTC(),
		})
		return nil
	}

	s.active = aggregator.Merge(nil, nil, aggregator.MergeOptions{
		Profile: polCfg.Profile,
		Target:  s.cfg.Workspace,
		Policy:  polCfg,
		Now:     time.Now().UTC(),
	})
	return nil
}

// Handler returns the hardened HTTP handler wrapped in security headers and CSRF/auth checks.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/assets/", s.handleAssets)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api/v1/status", s.handleStatus)
	mux.HandleFunc("/api/v1/doctor", s.handleDoctor)
	mux.HandleFunc("/api/v1/report", s.handleGetReport)
	mux.HandleFunc("/api/v1/export", s.handleExport)
	mux.HandleFunc("/api/v1/scan", s.handlePostScan)
	mux.HandleFunc("/api/v1/history", s.handleHistory)
	mux.HandleFunc("/api/v1/playbooks", s.handleListPlaybooks)
	mux.HandleFunc("/api/v1/playbooks/run", s.handleRunPlaybook)
	mux.HandleFunc("/api/v1/attack-matrix", s.handleAttackMatrix)
	mux.HandleFunc("/api/v1/fix-preview", s.handleFixPreview)
	mux.HandleFunc("/api/v1/mcp-catalog", s.handleMCPCatalog)
	mux.HandleFunc("/api/v1/waivers", s.handleAddWaiver)
	mux.HandleFunc("/api/v1/siem/health", s.handleSIEMHealth)
	mux.HandleFunc("/api/v1/siem/ingest", s.handleSIEMIngest)
	mux.HandleFunc("/api/v1/assistant/config", s.handleAssistantConfig)
	mux.HandleFunc("/api/v1/assistant/chat", s.handleAssistantChat)
	mux.HandleFunc("/api/v1/events", s.handleSSE)

	return s.securityMiddleware(mux)
}

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Content-Security-Policy", strictCSP)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")

		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
			if !s.authorizeRequest(r) {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized: valid token or session cookie required")
				return
			}
			if r.Method == http.MethodPost && !isSameOriginPost(r) {
				writeJSONError(w, http.StatusForbidden, "cross-origin POST blocked by anti-CSRF guard")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) authorizeRequest(r *http.Request) bool {
	if s.cfg.NoAuth {
		return true
	}
	cand := strings.TrimSpace(r.Header.Get("X-Raksa-Token"))
	if cand == "" {
		if authz := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			cand = strings.TrimSpace(authz[7:])
		}
	}
	if cand == "" {
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			cand = strings.TrimSpace(cookie.Value)
		}
	}
	if cand == "" {
		return false
	}
	_, _, ok := s.auth.ValidateToken(r.Context(), cand)
	return ok
}

func isSameOriginPost(r *http.Request) bool {
	if sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); sfs != "" && sfs != "same-origin" && sfs != "none" {
		return false
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		if !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	return true
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if !s.cfg.NoAuth {
		if qTok := strings.TrimSpace(r.URL.Query().Get("token")); qTok != "" {
			if subtle.ConstantTimeCompare([]byte(qTok), []byte(s.cfg.Token)) == 1 {
				http.SetCookie(w, &http.Cookie{
					Name:     sessionCookieName,
					Value:    s.cfg.Token,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
					Secure:   r.TLS != nil,
				})
				w.Header().Set("Cache-Control", "no-store")
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			writeJSONError(w, http.StatusUnauthorized, "invalid bootstrap token")
			return
		}
	}

	raw, err := fs.ReadFile(s.assetSub, "index.html")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "embedded index missing")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/assets/")
	clean := filepath.ToSlash(filepath.Clean(rel))
	if clean == "." || strings.Contains(clean, "..") || strings.Contains(clean, "/") {
		http.NotFound(w, r)
		return
	}
	raw, err := fs.ReadFile(s.assetSub, clean)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if ct := mime.TypeByExtension(filepath.Ext(clean)); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"tool":    schema.ToolName,
		"version": schema.Version,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":       schema.Version,
		"schema":        schema.SchemaVersion,
		"edition":       ext.DefaultEdition(),
		"workspace":     s.cfg.Workspace,
		"from_reports":  s.cfg.FromReports,
		"siem_url":      s.cfg.SIEMURL,
		"auth_required": !s.cfg.NoAuth,
	})
}

func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	tools := runner.Doctor(r.Context(), s.cfg.BinDir, s.cfg.Resolver, s.cfg.Exec)
	writeJSON(w, http.StatusOK, map[string]any{"tools": tools})
}

func (s *Server) handleGetReport(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	rep := s.active
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	fmtKind, err := report.ParseFormat(r.URL.Query().Get("format"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.RLock()
	rep := s.active
	s.mu.RUnlock()

	rendered, err := report.Render(rep, fmtKind)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	extName := string(fmtKind)
	ct := "application/json; charset=utf-8"
	switch fmtKind {
	case report.FormatMarkdown:
		extName = "md"
		ct = "text/markdown; charset=utf-8"
	case report.FormatHTML:
		ct = "text/html; charset=utf-8"
	case report.FormatTable:
		extName = "txt"
		ct = "text/plain; charset=utf-8"
	case report.FormatSARIF:
		extName = "sarif.json"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"raksa-report.%s\"", extName))
	_, _ = w.Write(rendered)
}

type scanBody struct {
	Target      string   `json:"target"`
	Profile     string   `json:"profile"`
	Layers      []string `json:"layers"`
	FromReports string   `json:"from_reports"`
}

func (s *Server) handlePostScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body scanBody
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	rep, err := s.executeScan(r.Context(), body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) executeScan(ctx context.Context, body scanBody) (schema.SuiteReport, error) {
	target := strings.TrimSpace(body.Target)
	if target == "" {
		target = s.cfg.Workspace
	}
	profile := strings.TrimSpace(body.Profile)
	if profile == "" {
		profile = "full"
	}
	cfg, _, err := policy.Discover(target, "")
	if err != nil {
		return schema.SuiteReport{}, err
	}

	s.emitEvent("scan_started", fmt.Sprintf("Executing Hybrid audit (profile=%s, target=%s)", profile, target))

	var ups []aggregator.UpstreamReport
	var execs []schema.LayerExecution
	fromPath := strings.TrimSpace(body.FromReports)
	if fromPath == "" && s.cfg.FromReports != "" && len(body.Layers) == 0 {
		fromPath = s.cfg.FromReports
	}

	if fromPath != "" {
		ups, err = aggregator.LoadReportsFromPath(fromPath)
		if err != nil {
			return schema.SuiteReport{}, err
		}
	} else {
		ups, execs, err = runner.RunSuite(ctx, runner.SuiteRequest{
			Profile:        profile,
			ExplicitLayers: body.Layers,
			Target:         target,
			BinDir:         s.cfg.BinDir,
			Policy:         cfg,
		}, s.cfg.Resolver, s.cfg.Exec)
		if err != nil {
			return schema.SuiteReport{}, err
		}
	}

	rep := aggregator.Merge(ups, execs, aggregator.MergeOptions{
		Profile: profile,
		Target:  target,
		Policy:  cfg,
		Now:     time.Now().UTC(),
	})

	if _, histErr := s.history.Append(rep); histErr == nil {
		s.emitEvent("ledger_appended", fmt.Sprintf("Recorded scan #%d (%d/100 %s)", rep.Summary.Total, rep.Posture.Score, rep.Posture.Grade))
	}

	s.mu.Lock()
	s.active = rep
	s.mu.Unlock()

	s.emitEvent("scan_completed", fmt.Sprintf("Audit complete: %d/100 (%s), %d active finding(s)", rep.Posture.Score, rep.Posture.Grade, rep.Summary.Total))
	return rep, nil
}

func (s *Server) handleHistory(w http.ResponseWriter, _ *http.Request) {
	count, ok, reason, err := s.history.VerifyChain()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	runs, err := s.history.List(25)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"history_path":   s.cfg.HistoryPath,
		"chain_entries":  count,
		"chain_verified": ok,
		"chain_reason":   reason,
		"runs":           runs,
	})
}

func (s *Server) handleListPlaybooks(w http.ResponseWriter, _ *http.Request) {
	pbs, err := playbook.ListBuiltins()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"playbooks": pbs})
}

func (s *Server) handleRunPlaybook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		Name   string `json:"name"`
		Target string `json:"target"`
	}
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	pb, err := playbook.ResolveBuiltin(req.Name)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	rep, err := s.executeScan(r.Context(), scanBody{
		Target:  req.Target,
		Profile: pb.Name,
		Layers:  pb.Layers,
	})
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleAttackMatrix(w http.ResponseWriter, r *http.Request) {
	rows := schema.AttackDefenseMatrix()
	if filter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status"))); filter != "" {
		filtered := make([]schema.AttackCoverageRow, 0, len(rows))
		for _, row := range rows {
			if row.Status == filter {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"matrix": rows})
}

func (s *Server) handleFixPreview(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("path"))
	if target == "" {
		target = s.cfg.Workspace
	}
	res := remediate.CollectFixPreviews(r.Context(), target, s.cfg.Remediate)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleMCPCatalog(w http.ResponseWriter, _ *http.Request) {
	specs := mcphub.Catalog()
	type catalogDTO struct {
		Name        string `json:"name"`
		Layer       string `json:"layer"`
		Binary      string `json:"binary"`
		Description string `json:"description"`
	}
	out := make([]catalogDTO, 0, len(specs))
	for _, sp := range specs {
		out = append(out, catalogDTO{
			Name:        sp.Name,
			Layer:       sp.Layer,
			Binary:      sp.Binary,
			Description: sp.Description,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": len(out), "tools": out})
}

func (s *Server) handleAddWaiver(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var wv policy.Waiver
	if err := decodeJSONBody(r.Body, &wv); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	cfg, cfgPath, err := policy.Discover(s.cfg.Workspace, "")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if cfgPath == "" {
		cfgPath = filepath.Join(s.cfg.Workspace, policy.DefaultConfigFilename)
	}
	cfg.Waivers = append(cfg.Waivers, wv)
	if err := cfg.Validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	rawYAML, err := yaml.Marshal(&cfg)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := os.WriteFile(cfgPath, rawYAML, 0o600); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("write %s: %v", cfgPath, err))
		return
	}

	s.mu.Lock()
	remaining, suppressed := policy.ApplyWaivers(s.active.Findings, cfg.Waivers, time.Now().UTC())
	s.active.Findings = remaining
	s.active.SuppressedCount += suppressed
	s.active.Summary = schema.BuildSummary(remaining)
	s.active.Posture = schema.ComputePosture(remaining)
	updated := s.active
	s.mu.Unlock()

	s.emitEvent("waiver_added", fmt.Sprintf("Saved fail-closed waiver for %s (exp %s)", wv.RuleID, wv.ExpiresOn))
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleSIEMHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	endpoint := s.resolveSIEMEndpoint(r)
	client, err := bridge.NewClient(endpoint, s.cfg.SIEMToken, 8*time.Second)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := client.Health(r.Context()); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.emitEvent("siem_health", fmt.Sprintf("SIEM reachable at %s", endpoint))
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "endpoint": endpoint})
}

func (s *Server) handleSIEMIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	endpoint := s.resolveSIEMEndpoint(r)
	client, err := bridge.NewClient(endpoint, s.cfg.SIEMToken, 10*time.Second)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.RLock()
	rep := s.active
	s.mu.RUnlock()

	res, err := client.IngestReport(r.Context(), rep)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.mu.Lock()
	s.active.SIEMIngested = true
	s.mu.Unlock()

	s.emitEvent("siem_ingest", fmt.Sprintf("Pushed suite report (%d findings) to %s", rep.Summary.Total, endpoint))
	writeJSON(w, http.StatusOK, map[string]any{"endpoint": endpoint, "response": res})
}

func (s *Server) handleAssistantConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	writeJSON(w, http.StatusOK, assistant.GetConfigStatus())
}

func (s *Server) handleAssistantChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req assistant.ChatRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.mu.RLock()
	rep := s.active
	s.mu.RUnlock()

	res, err := assistant.Chat(r.Context(), assistant.InputContext{
		Report:      rep,
		Workspace:   s.cfg.Workspace,
		BinDir:      s.cfg.BinDir,
		HistoryPath: s.cfg.HistoryPath,
		Resolver:    s.cfg.Resolver,
		Exec:        s.cfg.Exec,
		Remediate:   s.cfg.Remediate,
	}, req)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.emitEvent("assistant_reply", fmt.Sprintf("AI Defense Assistant answered in %s mode (%d tool checks)", res.Mode, len(res.ToolCalls)))
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) resolveSIEMEndpoint(r *http.Request) string {
	var body struct {
		SIEMURL string `json:"siem_url"`
	}
	_ = decodeJSONBody(r.Body, &body)
	if strings.TrimSpace(body.SIEMURL) != "" {
		return strings.TrimSpace(body.SIEMURL)
	}
	if strings.TrimSpace(s.cfg.SIEMURL) != "" {
		return s.cfg.SIEMURL
	}
	return "http://127.0.0.1:8484"
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan SSEEvent, 16)
	s.subMu.Lock()
	s.subs[ch] = struct{}{}
	s.subMu.Unlock()
	defer func() {
		s.subMu.Lock()
		delete(s.subs, ch)
		close(ch)
		s.subMu.Unlock()
	}()

	initial, _ := json.Marshal(SSEEvent{
		Type:      "connected",
		Message:   fmt.Sprintf("Subscribed to Raksa v%s workbench telemetry", schema.Version),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	_, _ = fmt.Fprintf(w, "data: %s\n\n", initial)
	flusher.Flush()

	keepAlive := time.NewTicker(25 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			payload, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
		case <-keepAlive.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) emitEvent(kind, message string) {
	ev := SSEEvent{
		Type:      kind,
		Message:   message,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	s.subMu.Lock()
	for ch := range s.subs {
		select {
		case ch <- ev:
		default:
		}
	}
	s.subMu.Unlock()
}

func generateToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func decodeJSONBody(r io.Reader, dst any) error {
	raw, err := io.ReadAll(io.LimitReader(r, 1024*1024))
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(trimmed), dst); err != nil {
		return fmt.Errorf("invalid JSON payload: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}
