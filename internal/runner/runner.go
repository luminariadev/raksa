// Package runner implements Hybrid parallel Layer 1-6 orchestration, tool discovery,
// graceful degradation for missing binaries, and SHA-256 verified binary installation.
package runner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/luminariadev/raksa/internal/aggregator"
	"github.com/luminariadev/raksa/internal/policy"
	"github.com/luminariadev/raksa/internal/schema"
)

// ExecResult captures raw subprocess execution details.
type ExecResult struct {
	Stdout   []byte
	Stderr   string
	ExitCode int
	Err      error
}

// CommandRunner abstracts subprocess execution for deterministic tests.
type CommandRunner func(ctx context.Context, binary string, args ...string) ExecResult

// BinaryResolver abstracts binary lookup for doctor and runner tests.
type BinaryResolver func(binary string, binDir string) (string, bool)

// SuiteRequest describes a Hybrid L1-L6 execution target and layer filter.
type SuiteRequest struct {
	Profile        string
	ExplicitLayers []string
	Target         string
	NetPolicy      string
	NetLog         string
	WebURL         string
	BinDir         string
	Policy         policy.Config
	Concurrency    int
	Timeout        time.Duration
}

// InstallPlanItem describes an artifact URL and checksum source for a layer install.
type InstallPlanItem struct {
	Layer       string `json:"layer"`
	Binary      string `json:"binary"`
	Version     string `json:"version"`
	ArchiveURL  string `json:"archive_url"`
	ChecksumURL string `json:"checksum_url"`
	DestPath    string `json:"dest_path"`
}

func defaultCommandRunner(ctx context.Context, binary string, args ...string) ExecResult {
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return ExecResult{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      err,
	}
}

// DefaultBinDir returns ~/.raksa/bin (or .raksa/bin fallback).
func DefaultBinDir() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(".raksa", "bin")
	}
	return filepath.Join(home, ".raksa", "bin")
}

// ResolveBinary looks up a Raksa tool in binDir, PATH, and DefaultBinDir.
func ResolveBinary(binary, binDir string) (string, bool) {
	candidates := binaryCandidates(binary)
	searchDirs := make([]string, 0, 2)
	if strings.TrimSpace(binDir) != "" {
		searchDirs = append(searchDirs, binDir)
	}
	searchDirs = append(searchDirs, DefaultBinDir())

	for _, dir := range searchDirs {
		for _, cand := range candidates {
			full := filepath.Join(dir, cand)
			if info, err := os.Stat(full); err == nil && !info.IsDir() {
				return full, true
			}
		}
	}
	for _, cand := range candidates {
		if path, err := exec.LookPath(cand); err == nil {
			return path, true
		}
	}
	return "", false
}

func binaryCandidates(binary string) []string {
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(binary), ".exe") {
		return []string{binary + ".exe", binary}
	}
	return []string{binary}
}

// Doctor checks availability, version output, and binary SHA-256 across Layers 1-6.
func Doctor(ctx context.Context, binDir string, resolver BinaryResolver, execFn CommandRunner) []schema.ToolDoctorStatus {
	if resolver == nil {
		resolver = ResolveBinary
	}
	if execFn == nil {
		execFn = defaultCommandRunner
	}

	catalog := schema.LayerCatalog()
	out := make([]schema.ToolDoctorStatus, 0, len(catalog))
	for _, spec := range catalog {
		st := schema.ToolDoctorStatus{
			Number:     spec.Number,
			ID:         spec.ID,
			Binary:     spec.Binary,
			Repository: spec.Repository,
			RuleCount:  spec.RuleCount,
			MCPCount:   spec.MCPCount,
		}
		path, ok := resolver(spec.Binary, binDir)
		if !ok {
			st.Status = "missing"
			st.Hint = fmt.Sprintf("raksa install --layers %s", spec.ID)
			out = append(out, st)
			continue
		}
		st.Installed = true
		st.Path = path
		if digest, err := fileSHA256(path); err == nil {
			st.SHA256 = digest
		}

		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		res := execFn(cctx, path, "version")
		cancel()
		verLine := strings.TrimSpace(strings.Split(string(res.Stdout), "\n")[0])
		if res.ExitCode == 0 && verLine != "" {
			st.Status = "ready"
			st.Version = verLine
		} else if res.Err != nil {
			st.Status = "error"
			st.Hint = res.Err.Error()
		} else {
			st.Status = "ready"
			st.Version = "unknown"
		}
		out = append(out, st)
	}
	return out
}

// ResolveLayers computes the ordered Hybrid layer list from profile, explicit flags, and .raksa.yml.
func ResolveLayers(profile string, explicit []string, cfg policy.Config) ([]schema.LayerSpec, error) {
	catalog := schema.LayerCatalog()
	byID := make(map[string]schema.LayerSpec, len(catalog))
	for _, spec := range catalog {
		byID[spec.ID] = spec
	}

	var wanted []string
	if len(explicit) > 0 {
		for _, item := range explicit {
			for _, part := range strings.Split(item, ",") {
				trimmed := strings.TrimSpace(part)
				if trimmed == "" {
					continue
				}
				id, ok := schema.ParseLayerAlias(trimmed)
				if !ok {
					return nil, fmt.Errorf("unknown layer %q", trimmed)
				}
				if !slices.Contains(wanted, id) {
					wanted = append(wanted, id)
				}
			}
		}
	} else {
		p := strings.ToLower(strings.TrimSpace(profile))
		if p == "" {
			p = strings.ToLower(strings.TrimSpace(cfg.Profile))
		}
		switch p {
		case "", "full", "all":
			wanted = []string{"netguard", "hostguard", "webshield", "pipeguard", "iocscan", "siem"}
		case "repo", "ci":
			wanted = []string{"pipeguard", "hostguard", "webshield", "iocscan", "siem"}
		case "host":
			wanted = []string{"netguard", "hostguard", "iocscan", "siem"}
		case "web":
			wanted = []string{"webshield", "pipeguard", "hostguard"}
		case "incident", "dfir":
			wanted = []string{"iocscan", "hostguard", "netguard", "siem"}
		default:
			return nil, fmt.Errorf("unknown scan profile %q (expected full, repo, host, web, incident)", p)
		}

		if len(cfg.EnabledLayers) > 0 {
			enabled := make([]string, 0, len(cfg.EnabledLayers))
			for _, raw := range cfg.EnabledLayers {
				if id, ok := schema.ParseLayerAlias(raw); ok && !slices.Contains(enabled, id) {
					enabled = append(enabled, id)
				}
			}
			wanted = enabled
		}
	}

	disabled := make(map[string]bool)
	for _, raw := range cfg.DisabledLayers {
		if id, ok := schema.ParseLayerAlias(raw); ok {
			disabled[id] = true
		}
	}

	resolved := make([]schema.LayerSpec, 0, len(wanted))
	for _, id := range wanted {
		if len(explicit) == 0 && disabled[id] {
			continue
		}
		if spec, ok := byID[id]; ok {
			resolved = append(resolved, spec)
		}
	}
	if len(resolved) == 0 {
		return nil, fmt.Errorf("no runnable layers remain after applying filters")
	}
	return resolved, nil
}

// RunSuite executes selected L1-L5 tools concurrently, gracefully skips missing binaries,
// and optionally feeds upstream findings into L6 raksa-siem correlate.
func RunSuite(ctx context.Context, req SuiteRequest, resolver BinaryResolver, execFn CommandRunner) ([]aggregator.UpstreamReport, []schema.LayerExecution, error) {
	if resolver == nil {
		resolver = ResolveBinary
	}
	if execFn == nil {
		execFn = defaultCommandRunner
	}
	if strings.TrimSpace(req.Target) == "" {
		req.Target = "."
	}
	if req.Timeout <= 0 {
		if req.Policy.PerLayerTimeoutSec > 0 {
			req.Timeout = time.Duration(req.Policy.PerLayerTimeoutSec) * time.Second
		} else {
			req.Timeout = 120 * time.Second
		}
	}
	conc := req.Concurrency
	if conc <= 0 {
		conc = req.Policy.MaxConcurrency
	}
	if conc <= 0 {
		conc = 4
	}

	specs, err := ResolveLayers(req.Profile, req.ExplicitLayers, req.Policy)
	if err != nil {
		return nil, nil, err
	}

	var preSIEM []schema.LayerSpec
	var siemSpec *schema.LayerSpec
	for i := range specs {
		if specs[i].ID == "siem" {
			copySpec := specs[i]
			siemSpec = &copySpec
		} else {
			preSIEM = append(preSIEM, specs[i])
		}
	}

	execMap := make(map[string]schema.LayerExecution, len(specs))
	reports := make([]aggregator.UpstreamReport, 0, len(specs))
	var mu sync.Mutex
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for _, spec := range preSIEM {
		wg.Add(1)
		go func(sp schema.LayerSpec) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rep, ex := executeUpstreamLayer(ctx, sp, req, resolver, execFn)
			mu.Lock()
			execMap[sp.ID] = ex
			if rep != nil {
				reports = append(reports, *rep)
			}
			mu.Unlock()
		}(spec)
	}
	wg.Wait()

	if siemSpec != nil {
		var allUpstream []schema.Finding
		for _, r := range reports {
			allUpstream = append(allUpstream, r.Findings...)
		}
		rep, ex := executeSIEMCorrelate(ctx, *siemSpec, req, allUpstream, resolver, execFn)
		execMap[siemSpec.ID] = ex
		if rep != nil {
			reports = append(reports, *rep)
		}
	}

	orderedExec := make([]schema.LayerExecution, 0, len(specs))
	for _, sp := range specs {
		if ex, ok := execMap[sp.ID]; ok {
			orderedExec = append(orderedExec, ex)
		}
	}
	return reports, orderedExec, nil
}

func executeUpstreamLayer(ctx context.Context, sp schema.LayerSpec, req SuiteRequest, resolver BinaryResolver, execFn CommandRunner) (*aggregator.UpstreamReport, schema.LayerExecution) {
	ex := schema.LayerExecution{
		Layer:  sp.ID,
		Binary: sp.Binary,
	}
	binPath, found := resolver(sp.Binary, req.BinDir)
	if !found {
		ex.Status = "not_installed"
		ex.Message = fmt.Sprintf("install with 'raksa install --layers %s'", sp.ID)
		return nil, ex
	}

	args, skipReason := buildLayerArgs(sp.ID, req)
	if skipReason != "" {
		ex.Status = "skipped"
		ex.Message = skipReason
		return nil, ex
	}

	started := time.Now()
	cctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	res := execFn(cctx, binPath, args...)
	ex.DurationMs = time.Since(started).Milliseconds()
	ex.ExitCode = res.ExitCode

	trimmed := bytes.TrimSpace(res.Stdout)
	if len(trimmed) > 0 && (res.ExitCode == 0 || res.ExitCode == 2) {
		parsed, err := aggregator.ParseReportBytes(trimmed, sp.Binary)
		if err == nil {
			ex.Status = "ok"
			if len(parsed.Findings) > 0 {
				ex.Status = "findings"
			}
			return &parsed, ex
		}
		ex.Status = "error"
		ex.Message = fmt.Sprintf("parse output: %v", err)
		return nil, ex
	}

	ex.Status = "error"
	if res.Stderr != "" {
		ex.Message = strings.TrimSpace(res.Stderr)
	} else if res.Err != nil {
		ex.Message = res.Err.Error()
	} else {
		ex.Message = fmt.Sprintf("%s exited with code %d", sp.Binary, res.ExitCode)
	}
	return nil, ex
}

func executeSIEMCorrelate(ctx context.Context, sp schema.LayerSpec, req SuiteRequest, upstream []schema.Finding, resolver BinaryResolver, execFn CommandRunner) (*aggregator.UpstreamReport, schema.LayerExecution) {
	ex := schema.LayerExecution{
		Layer:  sp.ID,
		Binary: sp.Binary,
	}
	binPath, found := resolver(sp.Binary, req.BinDir)
	if !found {
		ex.Status = "not_installed"
		ex.Message = "install with 'raksa install --layers siem'"
		return nil, ex
	}
	if len(upstream) == 0 {
		ex.Status = "ok"
		ex.Message = "no upstream findings to correlate"
		return nil, ex
	}

	ndjson, err := aggregator.ToNDJSON(upstream)
	if err != nil {
		ex.Status = "error"
		ex.Message = err.Error()
		return nil, ex
	}
	tmpFile, err := os.CreateTemp("", "raksa-l7-upstream-*.ndjson")
	if err != nil {
		ex.Status = "error"
		ex.Message = fmt.Sprintf("create temp ndjson: %v", err)
		return nil, ex
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if _, err := tmpFile.Write(ndjson); err != nil {
		_ = tmpFile.Close()
		ex.Status = "error"
		ex.Message = fmt.Sprintf("write temp ndjson: %v", err)
		return nil, ex
	}
	_ = tmpFile.Close()

	started := time.Now()
	cctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	res := execFn(cctx, binPath, "correlate", tmpPath, "--output", "json", "--fail-on", "critical")
	ex.DurationMs = time.Since(started).Milliseconds()
	ex.ExitCode = res.ExitCode

	trimmed := bytes.TrimSpace(res.Stdout)
	if len(trimmed) > 0 && (res.ExitCode == 0 || res.ExitCode == 1 || res.ExitCode == 2) {
		parsed, parseErr := aggregator.ParseReportBytes(trimmed, sp.Binary)
		if parseErr == nil {
			ex.Status = "ok"
			if len(parsed.Findings) > 0 {
				ex.Status = "findings"
			}
			return &parsed, ex
		}
	}

	ex.Status = "error"
	ex.Message = strings.TrimSpace(res.Stderr)
	if ex.Message == "" && res.Err != nil {
		ex.Message = res.Err.Error()
	}
	return nil, ex
}

func buildLayerArgs(layerID string, req SuiteRequest) ([]string, string) {
	switch layerID {
	case "netguard":
		if strings.TrimSpace(req.NetPolicy) != "" {
			return []string{"audit", "--policy", req.NetPolicy, "--format", "json"}, ""
		}
		if strings.TrimSpace(req.NetLog) != "" {
			return []string{"analyze", "--log", req.NetLog, "--format", "json"}, ""
		}
		for _, candidate := range []string{".netguard.yml", "netguard.yml", "netguard-policy.yml"} {
			p := filepath.Join(req.Target, candidate)
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				return []string{"audit", "--policy", p, "--format", "json"}, ""
			}
		}
		return nil, "pass --net-policy <yaml> or --net-log <file> to scan Layer 1"
	case "hostguard":
		return []string{"audit-workspace", "--path", req.Target, "--format", "json"}, ""
	case "webshield":
		if strings.TrimSpace(req.WebURL) != "" {
			return []string{"audit-headers", "--url", req.WebURL, "--format", "json"}, ""
		}
		return []string{"audit-workspace", "--path", req.Target, "--format", "json"}, ""
	case "pipeguard":
		return []string{"scan-repo", "--path", req.Target, "--format", "json", "--fail-on", "none"}, ""
	case "iocscan":
		return []string{"scan", "--path", req.Target, "--format", "json", "--fail-on", "none"}, ""
	default:
		return nil, fmt.Sprintf("unsupported layer %s", layerID)
	}
}

// PlanInstall constructs official GitHub release artifact and SHA-256 URLs for requested layers.
func PlanInstall(layers []string, destDir, goos, goarch string) ([]InstallPlanItem, error) {
	if strings.TrimSpace(destDir) == "" {
		destDir = DefaultBinDir()
	}
	catalog := schema.LayerCatalog()
	byID := make(map[string]schema.LayerSpec, len(catalog))
	for _, spec := range catalog {
		byID[spec.ID] = spec
	}

	var ids []string
	if len(layers) == 0 {
		for _, spec := range catalog {
			if spec.ID != "iocscan" {
				ids = append(ids, spec.ID)
			}
		}
	} else {
		for _, raw := range layers {
			for _, part := range strings.Split(raw, ",") {
				id, ok := schema.ParseLayerAlias(part)
				if !ok {
					return nil, fmt.Errorf("unknown layer %q", part)
				}
				if !slices.Contains(ids, id) {
					ids = append(ids, id)
				}
			}
		}
	}

	items := make([]InstallPlanItem, 0, len(ids))
	for _, id := range ids {
		sp := byID[id]
		tag := "v" + sp.Version
		base := fmt.Sprintf("https://github.com/%s/releases/download/%s", sp.Repository, tag)
		archiveName, checksumFile, err := releaseArtifactNames(sp, tag, goos, goarch)
		if err != nil {
			return nil, err
		}
		binName := sp.Binary
		if goos == "windows" && sp.ID != "iocscan" {
			binName += ".exe"
		}
		items = append(items, InstallPlanItem{
			Layer:       sp.ID,
			Binary:      sp.Binary,
			Version:     tag,
			ArchiveURL:  base + "/" + archiveName,
			ChecksumURL: base + "/" + checksumFile,
			DestPath:    filepath.Join(destDir, binName),
		})
	}
	return items, nil
}

func releaseArtifactNames(sp schema.LayerSpec, tag, goos, goarch string) (archive string, checksum string, err error) {
	ext := "tar.gz"
	if goos == "windows" {
		ext = "zip"
	}
	switch sp.ID {
	case "hostguard":
		target := ""
		switch {
		case goos == "linux" && goarch == "amd64":
			target = "x86_64-unknown-linux-musl"
		case goos == "windows" && goarch == "amd64":
			target = "x86_64-pc-windows-msvc"
		case goos == "darwin" && goarch == "arm64":
			target = "aarch64-apple-darwin"
		default:
			return "", "", fmt.Errorf("raksa-hostguard prebuilt release unavailable for %s/%s (build via cargo install)", goos, goarch)
		}
		return fmt.Sprintf("raksa-hostguard-%s-%s.%s", tag, target, ext), "SHA256SUMS.txt", nil
	case "iocscan":
		return fmt.Sprintf("raksa_iocscan-%s-py3-none-any.whl", sp.Version), "SHA256SUMS.txt", nil
	case "siem":
		return fmt.Sprintf("%s-%s-%s-%s.%s", sp.Binary, tag, goos, goarch, ext), "checksums-sha256.txt", nil
	default:
		return fmt.Sprintf("%s-%s-%s-%s.%s", sp.Binary, tag, goos, goarch, ext), "SHA256SUMS.txt", nil
	}
}

// InstallBinaryArchive downloads archive + checksum manifest, enforces SHA-256 verification, and extracts the binary.
func InstallBinaryArchive(ctx context.Context, item InstallPlanItem) error {
	if strings.HasSuffix(item.ArchiveURL, ".whl") {
		return fmt.Errorf("%s is distributed as a Python package; install with 'pipx install %s' or 'pip install %s'", item.Binary, item.ArchiveURL, item.ArchiveURL)
	}
	checksumBytes, err := downloadBytes(ctx, item.ChecksumURL, 1024*1024)
	if err != nil {
		return fmt.Errorf("download checksum for %s: %w", item.Binary, err)
	}
	archiveName := filepath.Base(item.ArchiveURL)
	wantHash, err := findChecksumInManifest(string(checksumBytes), archiveName)
	if err != nil {
		return err
	}
	archiveBytes, err := downloadBytes(ctx, item.ArchiveURL, 128*1024*1024)
	if err != nil {
		return fmt.Errorf("download archive for %s: %w", item.Binary, err)
	}
	sum := sha256.Sum256(archiveBytes)
	gotHash := hex.EncodeToString(sum[:])
	if !strings.EqualFold(gotHash, wantHash) {
		return fmt.Errorf("SHA-256 mismatch for %s: expected %s got %s", archiveName, wantHash, gotHash)
	}
	if err := os.MkdirAll(filepath.Dir(item.DestPath), 0o755); err != nil {
		return fmt.Errorf("create bin dir: %w", err)
	}
	return extractBinaryFromArchive(archiveBytes, archiveName, item.DestPath)
}

func downloadBytes(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "raksa-orchestrator/"+schema.Version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, rawURL)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("download %s exceeds %d byte limit", rawURL, maxBytes)
	}
	return data, nil
}

func findChecksumInManifest(manifest, targetFile string) (string, error) {
	for _, line := range strings.Split(manifest, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		name := filepath.Base(strings.TrimPrefix(fields[1], "*"))
		if name == targetFile {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("checksum entry for %s not found in manifest", targetFile)
}

func extractBinaryFromArchive(archiveBytes []byte, archiveName, destPath string) error {
	wantBase := filepath.Base(destPath)
	if strings.HasSuffix(strings.ToLower(archiveName), ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(archiveBytes), int64(len(archiveBytes)))
		if err != nil {
			return fmt.Errorf("open zip: %w", err)
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() || filepath.Base(f.Name) != wantBase {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()
			raw, err := io.ReadAll(io.LimitReader(rc, 64*1024*1024))
			if err != nil {
				return err
			}
			return os.WriteFile(destPath, raw, 0o755)
		}
		return fmt.Errorf("binary %s not found in zip archive", wantBase)
	}

	gz, err := gzip.NewReader(bytes.NewReader(archiveBytes))
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != wantBase {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(tr, 64*1024*1024))
		if err != nil {
			return err
		}
		return os.WriteFile(destPath, raw, 0o755)
	}
	return fmt.Errorf("binary %s not found in tar.gz archive", wantBase)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
