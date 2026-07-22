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
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

func main() {
	os.Exit(run())
}

func run() int {
	args := os.Args[1:]
	if len(args) == 0 {
		printUsage()
		return 1
	}

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	case "access-request":
		return cmdAccessRequest(cmdArgs)
	case "totp-code":
		return cmdTOTPCode(cmdArgs)
	case "device-register":
		return cmdDeviceRegister(cmdArgs)
	case "approve-push":
		return cmdApprovePush(cmdArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		return 1
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: simulator <command>

Commands:
  access-request --server <url> --token <token> --file <json>
  totp-code --secret <secret>
  device-register --server <url> --token <token> --identity-id <id> --name <name>
  approve-push --server <url> --token <token> --challenge-id <id> --device-id <id> --secret <secret> --number <n>`)
}

func cmdAccessRequest(args []string) int {
	fs := flag.NewFlagSet("access-request", flag.ContinueOnError)
	server := fs.String("server", "", "server URL")
	token := fs.String("token", "", "auth token")
	file := fs.String("file", "", "path to access request JSON file")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *server == "" || *token == "" || *file == "" {
		fmt.Fprintln(os.Stderr, "--server, --token, and --file are required")
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

	resp, err := apiCall(*server, *token, "POST", "/v1/access/evaluate", req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	printJSON(resp)
	return 0
}

func cmdTOTPCode(args []string) int {
	fs := flag.NewFlagSet("totp-code", flag.ContinueOnError)
	secret := fs.String("secret", "", "TOTP secret")
	if err := fs.Parse(args); err != nil {
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
	fmt.Println(code)
	return 0
}

func cmdDeviceRegister(args []string) int {
	fs := flag.NewFlagSet("device-register", flag.ContinueOnError)
	server := fs.String("server", "", "server URL")
	token := fs.String("token", "", "auth token")
	identityID := fs.String("identity-id", "", "identity ID")
	name := fs.String("name", "", "device name")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *server == "" || *token == "" || *identityID == "" || *name == "" {
		fmt.Fprintln(os.Stderr, "--server, --token, --identity-id, and --name are required")
		return 1
	}

	body := map[string]interface{}{
		"name": *name,
		"type": "push",
	}

	resp, err := apiCall(*server, *token, "POST", "/v1/identities/"+*identityID+"/factors/push/enroll", body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	printJSON(resp)
	return 0
}

func cmdApprovePush(args []string) int {
	fs := flag.NewFlagSet("approve-push", flag.ContinueOnError)
	server := fs.String("server", "", "server URL")
	token := fs.String("token", "", "auth token")
	challengeID := fs.String("challenge-id", "", "challenge ID")
	deviceID := fs.String("device-id", "", "device ID")
	secret := fs.String("secret", "", "device secret")
	number := fs.Int("number", 0, "push number to approve")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *server == "" || *token == "" || *challengeID == "" || *deviceID == "" || *secret == "" {
		fmt.Fprintln(os.Stderr, "--server, --token, --challenge-id, --device-id, and --secret are required")
		return 1
	}

	body := map[string]interface{}{
		"method":    "push",
		"device_id": *deviceID,
		"secret":    *secret,
		"number":    *number,
	}

	resp, err := apiCall(*server, *token, "POST", "/v1/challenge/"+*challengeID+"/verify", body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	printJSON(resp)
	return 0
}

func apiCall(server, token, method, path string, body interface{}) (map[string]interface{}, error) {
	url := strings.TrimRight(server, "/") + path

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respData))
	}

	var result map[string]interface{}
	if len(respData) > 0 {
		if err := json.Unmarshal(respData, &result); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}
	}
	return result, nil
}

func printJSON(data interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(data)
}
