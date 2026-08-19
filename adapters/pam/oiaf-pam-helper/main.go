// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

// oiaf-pam-helper is the PAM-side enforcement point for OIAF. It is designed
// to be invoked from pam_exec.so (expose_authtok) during the auth phase:
//
//	auth  [success=ok default=ignore]  pam_exec.so  expose_authtok  /usr/local/bin/oiaf-pam-helper
//
// Flow:
//  1. Read the PAM environment (PAM_USER, PAM_SERVICE, PAM_TYPE, PAM_RHOST,
//     PAM_TTY). Non-auth PAM types pass through without an evaluation.
//  2. Build an AccessRequest and call the OIAF core /v1/access/evaluate.
//  3. Map the decision to a PAM exit code:
//     allow     -> PAM_SUCCESS (0)
//     deny      -> PAM_AUTH_ERR (7)
//     alert     -> PAM_SUCCESS (0) with a warning on stderr
//     challenge -> prompt for the TOTP code on the PAM TTY (stdin
//     fallback when no TTY is attached), verify it, then
//     allow on approval / deny on rejection.
//  4. Fail closed on any OIAF or transport error unless OIAF_PAM_FAIL_OPEN
//     is explicitly set (dangerous; intended for audited rollouts only).
//
// Exit codes: 0 = PAM_SUCCESS, 6 = PAM_CONV_ERR, 7 = PAM_AUTH_ERR,
// 8 = PAM_SYSTEM_ERR. Never logs secrets, TOTP codes, or authtok values.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/Schildkrote/oiaf/tools/adapter-sdk"
	"github.com/pquerna/otp/totp"
	"golang.org/x/term"
)

const (
	exitSuccess   = 0 // PAM_SUCCESS
	exitConvErr   = 6 // PAM_CONV_ERR
	exitAuthErr   = 7 // PAM_AUTH_ERR
	exitSysErr    = 8 // PAM_SYSTEM_ERR
	exitAuthtok   = 9 // PAM_AUTHTOK_ERR (unused; reserved for future authtok checks)
	_             = exitAuthtok
	defaultServer = "http://127.0.0.1:8080"
)

// pams that make no sense to challenge (account/session/open_session/...);
// the auth-phase decision is authoritative and the rest passes through.
var skipPAMTypes = map[string]bool{
	"account":       true,
	"session":       true,
	"open_session":  true,
	"close_session": true,
}

type config struct {
	server   string
	token    string
	timeout  time.Duration
	failOpen bool
	totpFile string // test seam: file containing a TOTP secret used to self-verify

	user    string
	groups  []string
	service string
	rhost   string
	tty     string
}

func logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "oiaf-pam-helper: "+format+"\n", args...)
}

func loadConfig() (*config, error) {
	cfg := &config{
		server:   envOr("OIAF_SERVER", defaultServer),
		token:    os.Getenv("OIAF_ADAPTER_TOKEN"),
		totpFile: os.Getenv("OIAF_PAM_TOTP_FILE"),
		user:     os.Getenv("PAM_USER"),
		service:  os.Getenv("PAM_SERVICE"),
		rhost:    os.Getenv("PAM_RHOST"),
		tty:      os.Getenv("PAM_TTY"),
	}
	if v := os.Getenv("OIAF_PAM_GROUPS"); v != "" {
		for _, g := range strings.Split(v, ",") {
			if g = strings.TrimSpace(g); g != "" {
				cfg.groups = append(cfg.groups, g)
			}
		}
	}
	if d := envInt("OIAF_PAM_TIMEOUT", 5); d > 0 {
		cfg.timeout = time.Duration(d) * time.Second
	} else {
		cfg.timeout = 5 * time.Second
	}
	if v := os.Getenv("OIAF_PAM_FAIL_OPEN"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("OIAF_PAM_FAIL_OPEN must be a boolean: %w", err)
		}
		cfg.failOpen = b
	}
	if cfg.user == "" {
		return nil, errors.New("PAM_USER not set")
	}
	if cfg.service == "" {
		return nil, errors.New("PAM_SERVICE not set")
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// buildRequest maps the PAM environment onto an OIAF AccessRequest. PAM does
// not hand the helper the user's groups; when they are known (e.g. exported
// by a preceding PAM module via OIAF_PAM_GROUPS) they are forwarded so group
// conditions can be evaluated server-side.
func buildRequest(cfg *config) map[string]interface{} {
	// ssh/logins are the sensitive services; sudo escalates to high.
	sensitivity := "medium"
	if cfg.service == "sudo" {
		sensitivity = "high"
	}
	ident := map[string]interface{}{
		"username": cfg.user,
		"type":     "person",
	}
	if len(cfg.groups) > 0 {
		ident["groups"] = cfg.groups
	}
	return map[string]interface{}{
		"identity": ident,
		"resource": map[string]interface{}{
			"type":        cfg.service,
			"name":        cfg.service,
			"sensitivity": sensitivity,
		},
		"protocol": map[string]interface{}{"name": "pam"},
		"source":   map[string]interface{}{},
		"device":   map[string]interface{}{"managed": false, "compliant": true},
		"context": map[string]interface{}{
			"mfa_recent":  false,
			"interactive": true,
		},
	}
}

func evaluate(ctx context.Context, cfg *config, req map[string]interface{}) (map[string]interface{}, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	client := sdk.New(cfg.server, cfg.token, sdk.WithTimeout(cfg.timeout))
	raw, err := client.EvaluateAccess(ctx, body)
	if err != nil {
		return nil, err
	}
	var decision map[string]interface{}
	if err := json.Unmarshal(raw, &decision); err != nil {
		return nil, fmt.Errorf("decode evaluate response: %w", err)
	}
	return decision, nil
}

// resolveChallenge prompts for and verifies a TOTP challenge.
func resolveChallenge(ctx context.Context, cfg *config, decision map[string]interface{}) error {
	ch, _ := decision["challenge"].(map[string]interface{})
	if ch == nil {
		return errors.New("challenge decision without challenge details")
	}
	id, _ := ch["id"].(string)
	if id == "" {
		return errors.New("challenge missing id")
	}
	if methods, ok := ch["methods"].([]interface{}); ok && len(methods) > 0 {
		if fmt.Sprintf("%v", methods[0]) != "totp" {
			return fmt.Errorf("unsupported challenge method: %v", methods[0])
		}
	}

	code, err := promptTOTP(cfg)
	if err != nil {
		return err
	}

	client := sdk.New(cfg.server, cfg.token, sdk.WithTimeout(cfg.timeout))
	raw, err := client.VerifyChallenge(ctx, id, []byte(`{"method":"totp","code":"`+code+`"}`))
	if err != nil {
		return err
	}
	var verified map[string]interface{}
	if err := json.Unmarshal(raw, &verified); err != nil {
		return fmt.Errorf("decode verify response: %w", err)
	}
	if status, _ := verified["status"].(string); status != "approved" {
		logf("challenge rejected (status=%s)", status)
		return errors.New("challenge not approved")
	}
	logf("challenge approved")
	return nil
}

// promptTOTP asks for a 6-digit code. It prefers the PAM TTY (pam_exec
// passes it via PAM_TTY; the console is not otherwise wired through) and
// falls back to stdin/stdout. The TOTP secret file seam (OIAF_PAM_TOTP_FILE)
// is for automated testing and dev demos, not interactive use.
func promptTOTP(cfg *config) (string, error) {
	if cfg.totpFile != "" {
		secret, err := os.ReadFile(cfg.totpFile)
		if err != nil {
			return "", fmt.Errorf("read totp file: %w", err)
		}
		code, err := totp.GenerateCode(strings.TrimSpace(string(secret)), time.Now())
		if err != nil {
			return "", err
		}
		return code, nil
	}

	if tty := openTTY(cfg.tty); tty != nil {
		defer tty.Close()
		fmt.Fprintf(tty, "OIAF: enter your 6-digit TOTP code: ")
		fd := int(tty.Fd())
		var orig *term.State
		if term.IsTerminal(fd) {
			if s, err := term.GetState(fd); err == nil {
				orig = s
				_, _ = term.MakeRaw(fd)
			}
		}
		line, err := bufio.NewReader(tty).ReadString('\n')
		if orig != nil {
			term.Restore(fd, orig)
			fmt.Fprintln(tty)
		}
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("read TOTP from %s: %w", tty.Name(), err)
		}
		code := strings.TrimSpace(line)
		if code == "" {
			return "", errors.New("no TOTP code provided")
		}
		return code, nil
	}

	// No TTY (non-interactive test/dev): stdin with echo left on.
	fmt.Fprintln(os.Stderr, "OIAF: enter your 6-digit TOTP code:")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", errors.New("no TOTP code on stdin")
	}
	code := strings.TrimSpace(scanner.Text())
	if code == "" {
		return "", errors.New("empty TOTP code")
	}
	return code, nil
}

func openTTY(path string) *os.File {
	if path == "" || path == "/dev/null" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil
	}
	if fi, err := f.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		f.Close()
		return nil
	}
	return f
}

// run is the full helper flow; it returns the process exit code.
func run(ctx context.Context, cfg *config) int {
	if skipPAMTypes[os.Getenv("PAM_TYPE")] {
		return exitSuccess
	}

	if cfg.token == "" {
		logf("no adapter token configured (OIAF_ADAPTER_TOKEN); failing %s", mode(cfg.failOpen))
		return fail(cfg.failOpen)
	}

	decision, err := evaluate(ctx, cfg, buildRequest(cfg))
	if err != nil {
		logf("evaluate failed: %v; failing %s", err, mode(cfg.failOpen))
		return fail(cfg.failOpen)
	}

	switch d, _ := decision["decision"].(string); d {
	case "allow":
		logf("allow (risk_score=%v, reasons=%v)", decision["risk_score"], decision["reasons"])
		return exitSuccess
	case "alert":
		logf("alert treated as allow (reasons=%v)", decision["reasons"])
		return exitSuccess
	case "deny":
		logf("deny (risk_score=%v, reasons=%v)", decision["risk_score"], decision["reasons"])
		return exitAuthErr
	case "challenge":
		if err := resolveChallenge(ctx, cfg, decision); err != nil {
			logf("challenge failed: %v", err)
			return exitAuthErr
		}
		return exitSuccess
	default:
		logf("unknown decision %q; failing %s", d, mode(cfg.failOpen))
		return fail(cfg.failOpen)
	}
}

func mode(failOpen bool) string {
	if failOpen {
		return "OPEN (OIAF_PAM_FAIL_OPEN)"
	}
	return "closed"
}

func fail(failOpen bool) int {
	if failOpen {
		return exitSuccess
	}
	return exitSysErr
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		// Misconfiguration of the helper itself: deny (fail closed) and
		// let the underlying PAM stack (pam_unix) proceed.
		logf("config error: %v; failing closed", err)
		os.Exit(exitSysErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout+2*time.Second)
	defer cancel()
	// pam_exec may run the helper in its own session; ignore signals so a
	// terminal hang (Ctrl+C on the console) does not kill logins mid-way.
	signal.Ignore(os.Interrupt)

	os.Exit(run(ctx, cfg))
}
