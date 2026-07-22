// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const version = "0.1.0"

type globalOpts struct {
	server string
	token  string
	output string
}

func main() {
	os.Exit(run())
}

func run() int {
	args := os.Args[1:]

	opts := globalOpts{}
	var remaining []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			if i+1 < len(args) {
				opts.server = args[i+1]
				i++
			}
		case "--token":
			if i+1 < len(args) {
				opts.token = args[i+1]
				i++
			}
		case "--output":
			if i+1 < len(args) {
				opts.output = args[i+1]
				i++
			}
		default:
			remaining = append(remaining, args[i:]...)
			i = len(args)
		}
	}

	if opts.server == "" {
		opts.server = os.Getenv("OIAF_SERVER")
	}
	if opts.server == "" {
		opts.server = "http://127.0.0.1:8080"
	}
	if opts.token == "" {
		opts.token = os.Getenv("OIAF_ADMIN_TOKEN")
	}
	if opts.token == "" {
		if data, err := os.ReadFile(".oiaf/admin-token"); err == nil {
			opts.token = strings.TrimSpace(string(data))
		}
	}
	if opts.output == "" {
		opts.output = "text"
	}

	if len(remaining) == 0 {
		printUsage()
		return 1
	}

	cmd := remaining[0]
	cmdArgs := remaining[1:]

	switch cmd {
	case "version":
		return cmdVersion(opts)
	case "server":
		return cmdServer(opts)
	case "seed":
		return cmdSeed(opts, cmdArgs)
	case "identity":
		return cmdIdentity(opts, cmdArgs)
	case "adapter":
		return cmdAdapter(opts, cmdArgs)
	case "policy":
		return cmdPolicy(opts, cmdArgs)
	case "evaluate":
		return cmdEvaluate(opts, cmdArgs)
	case "challenge":
		return cmdChallenge(opts, cmdArgs)
	case "totp":
		return cmdTOTP(opts, cmdArgs)
	case "audit":
		return cmdAudit(opts, cmdArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		return 1
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: oiafctl [--server URL] [--token TOKEN] [--output json|text] <command>

Commands:
  version
  server
  seed --dev
  identity create --username <name> --type <person|service_account> --groups <comma-separated>
  identity list
  identity get <id>
  adapter create --name <name> --type <type>
  adapter list
  policy apply <file>
  policy list
  evaluate --file <access_request.json>
  challenge verify <challenge_id> --method totp --code <code>
  totp generate-secret
  totp code --secret <secret>
  audit list
  audit verify`)
}

func cmdVersion(opts globalOpts) int {
	info := map[string]string{
		"version": version,
		"name":    "oiafctl",
	}
	return output(opts, info, fmt.Sprintf("oiafctl version %s", version))
}

func cmdServer(opts globalOpts) int {
	cmd := exec.Command("go", "run", "./core/cmd/oiafd")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start server: %v\n", err)
		fmt.Fprintln(os.Stderr, "you can also run: go run ./core/cmd/oiafd")
		return 1
	}
	return 0
}

func cmdSeed(opts globalOpts, args []string) int {
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	dev := fs.Bool("dev", false, "seed development data")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if !*dev {
		fmt.Fprintln(os.Stderr, "only --dev is supported")
		return 1
	}

	identity := map[string]interface{}{
		"username":     "demo-user",
		"display_name": "Demo User",
		"type":         "person",
		"groups":       []string{"engineering", "admin"},
		"email":        "demo@example.com",
		"privileged":   false,
		"usual_geo":    "US",
	}
	var identityResp map[string]interface{}
	if err := apiCall(opts, "POST", "/v1/identities", identity, &identityResp); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create demo identity: %v\n", err)
		return 1
	}
	fmt.Println("created demo identity: demo-user")

	policy := map[string]interface{}{
		"description": "Demo policy: challenge non-admin access to critical resources",
		"enabled":     true,
		"priority":    100,
		"effect":      "challenge",
		"conditions": map[string]interface{}{
			"resource_sensitivity": []string{"critical"},
			"identity_groups":      []string{"engineering"},
		},
		"challenge": map[string]interface{}{
			"methods": []string{"totp"},
		},
	}
	var policyResp map[string]interface{}
	if err := apiCall(opts, "POST", "/v1/policies", policy, &policyResp); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create demo policy: %v\n", err)
		return 1
	}
	fmt.Println("created demo policy")

	adapter := map[string]interface{}{
		"name":    "demo-adapter",
		"type":    "generic",
		"enabled": true,
	}
	var adapterResp map[string]interface{}
	if err := apiCall(opts, "POST", "/v1/adapters", adapter, &adapterResp); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create demo adapter: %v\n", err)
		return 1
	}
	fmt.Println("created demo adapter: demo-adapter")
	if token, ok := adapterResp["token"].(string); ok {
		fmt.Printf("adapter token: %s\n", token)
	}

	return 0
}

func cmdIdentity(opts globalOpts, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: oiafctl identity <create|list|get> ...")
		return 1
	}

	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("identity create", flag.ContinueOnError)
		username := fs.String("username", "", "username")
		itype := fs.String("type", "person", "identity type")
		groups := fs.String("groups", "", "comma-separated groups")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		if *username == "" {
			fmt.Fprintln(os.Stderr, "--username is required")
			return 1
		}
		body := map[string]interface{}{
			"username": *username,
			"type":     *itype,
		}
		if *groups != "" {
			body["groups"] = strings.Split(*groups, ",")
		}
		var resp map[string]interface{}
		if err := apiCall(opts, "POST", "/v1/identities", body, &resp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return output(opts, resp, fmt.Sprintf("created identity: %s", *username))
	case "list":
		var resp []interface{}
		if err := apiCall(opts, "GET", "/v1/identities", nil, &resp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return outputList(opts, resp, "identities")
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: oiafctl identity get <id>")
			return 1
		}
		var resp map[string]interface{}
		if err := apiCall(opts, "GET", "/v1/identities/"+args[1], nil, &resp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return output(opts, resp, formatMap(resp))
	default:
		fmt.Fprintf(os.Stderr, "unknown identity subcommand: %s\n", args[0])
		return 1
	}
}

func cmdAdapter(opts globalOpts, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: oiafctl adapter <create|list> ...")
		return 1
	}

	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("adapter create", flag.ContinueOnError)
		name := fs.String("name", "", "adapter name")
		atype := fs.String("type", "", "adapter type")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		if *name == "" || *atype == "" {
			fmt.Fprintln(os.Stderr, "--name and --type are required")
			return 1
		}
		body := map[string]interface{}{
			"name":    *name,
			"type":    *atype,
			"enabled": true,
		}
		var resp map[string]interface{}
		if err := apiCall(opts, "POST", "/v1/adapters", body, &resp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return output(opts, resp, formatMap(resp))
	case "list":
		var resp []interface{}
		if err := apiCall(opts, "GET", "/v1/adapters", nil, &resp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return outputList(opts, resp, "adapters")
	default:
		fmt.Fprintf(os.Stderr, "unknown adapter subcommand: %s\n", args[0])
		return 1
	}
}

func cmdPolicy(opts globalOpts, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: oiafctl policy <apply|list> ...")
		return 1
	}

	switch args[0] {
	case "apply":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: oiafctl policy apply <file>")
			return 1
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read file: %v\n", err)
			return 1
		}
		var policy map[string]interface{}
		if err := json.Unmarshal(data, &policy); err != nil {
			fmt.Fprintf(os.Stderr, "invalid JSON: %v\n", err)
			return 1
		}
		var resp map[string]interface{}
		if err := apiCall(opts, "POST", "/v1/policies", policy, &resp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return output(opts, resp, "policy applied")
	case "list":
		var resp []interface{}
		if err := apiCall(opts, "GET", "/v1/policies", nil, &resp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return outputList(opts, resp, "policies")
	default:
		fmt.Fprintf(os.Stderr, "unknown policy subcommand: %s\n", args[0])
		return 1
	}
}

func cmdEvaluate(opts globalOpts, args []string) int {
	fs := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	file := fs.String("file", "", "path to access request JSON file")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *file == "" {
		fmt.Fprintln(os.Stderr, "--file is required")
		return 1
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read file: %v\n", err)
		return 1
	}
	var req map[string]interface{}
	if err := json.Unmarshal(data, &req); err != nil {
		fmt.Fprintf(os.Stderr, "invalid JSON: %v\n", err)
		return 1
	}
	var resp map[string]interface{}
	if err := apiCall(opts, "POST", "/v1/access/evaluate", req, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return output(opts, resp, formatMap(resp))
}

func cmdChallenge(opts globalOpts, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: oiafctl challenge verify <challenge_id> --method totp --code <code>")
		return 1
	}

	switch args[0] {
	case "verify":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: oiafctl challenge verify <challenge_id> --method totp --code <code>")
			return 1
		}
		challengeID := args[1]
		fs := flag.NewFlagSet("challenge verify", flag.ContinueOnError)
		method := fs.String("method", "totp", "verification method")
		code := fs.String("code", "", "verification code")
		if err := fs.Parse(args[2:]); err != nil {
			return 1
		}
		body := map[string]interface{}{
			"method": *method,
			"code":   *code,
		}
		var resp map[string]interface{}
		if err := apiCall(opts, "POST", "/v1/challenge/"+challengeID+"/verify", body, &resp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return output(opts, resp, formatMap(resp))
	default:
		fmt.Fprintf(os.Stderr, "unknown challenge subcommand: %s\n", args[0])
		return 1
	}
}

func cmdTOTP(opts globalOpts, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: oiafctl totp <generate-secret|code> ...")
		return 1
	}

	switch args[0] {
	case "generate-secret":
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "OIAF",
			AccountName: "oiaf-user",
			Algorithm:   otp.AlgorithmSHA1,
			Digits:      otp.DigitsSix,
			Period:      30,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate secret: %v\n", err)
			return 1
		}
		result := map[string]string{
			"secret":      key.Secret(),
			"otpauth_uri": key.URL(),
		}
		return output(opts, result, fmt.Sprintf("secret: %s\notpauth_uri: %s", key.Secret(), key.URL()))
	case "code":
		fs := flag.NewFlagSet("totp code", flag.ContinueOnError)
		secret := fs.String("secret", "", "TOTP secret")
		if err := fs.Parse(args[1:]); err != nil {
			return 1
		}
		if *secret == "" {
			fmt.Fprintln(os.Stderr, "--secret is required")
			return 1
		}
		code, err := totp.GenerateCode(*secret, time.Now())
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate code: %v\n", err)
			return 1
		}
		result := map[string]string{"code": code}
		return output(opts, result, fmt.Sprintf("code: %s", code))
	default:
		fmt.Fprintf(os.Stderr, "unknown totp subcommand: %s\n", args[0])
		return 1
	}
}

func cmdAudit(opts globalOpts, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: oiafctl audit <list|verify>")
		return 1
	}

	switch args[0] {
	case "list":
		var resp []interface{}
		if err := apiCall(opts, "GET", "/v1/audit/events", nil, &resp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return outputList(opts, resp, "audit events")
	case "verify":
		var resp map[string]interface{}
		if err := apiCall(opts, "GET", "/v1/audit/verify", nil, &resp); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		return output(opts, resp, formatMap(resp))
	default:
		fmt.Fprintf(os.Stderr, "unknown audit subcommand: %s\n", args[0])
		return 1
	}
}

func apiCall(opts globalOpts, method, path string, body interface{}, result interface{}) error {
	url := strings.TrimRight(opts.server, "/") + path

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if opts.token != "" {
		req.Header.Set("Authorization", "Bearer "+opts.token)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp map[string]string
		if json.Unmarshal(respData, &errResp) == nil {
			if msg, ok := errResp["error"]; ok {
				return fmt.Errorf("server error (%d): %s", resp.StatusCode, msg)
			}
		}
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respData))
	}

	if result != nil && len(respData) > 0 {
		if err := json.Unmarshal(respData, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}
	return nil
}

func output(opts globalOpts, data interface{}, text string) int {
	if opts.output == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode output: %v\n", err)
			return 1
		}
	} else {
		fmt.Println(text)
	}
	return 0
}

func outputList(opts globalOpts, items []interface{}, label string) int {
	if opts.output == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(items); err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode output: %v\n", err)
			return 1
		}
	} else {
		if len(items) == 0 {
			fmt.Printf("no %s found\n", label)
			return 0
		}
		fmt.Printf("%s (%d):\n", label, len(items))
		for _, item := range items {
			if m, ok := item.(map[string]interface{}); ok {
				fmt.Printf("  %s\n", formatMap(m))
			}
		}
	}
	return 0
}

func formatMap(m map[string]interface{}) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return strings.Join(parts, " ")
}
