// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

func main() {
	username := os.Getenv("PAM_USER")
	service := os.Getenv("PAM_SERVICE")
	rhost := os.Getenv("PAM_RHOST")
	tty := os.Getenv("PAM_TTY")

	if username == "" {
		fmt.Fprintln(os.Stderr, "oiaf-pam-helper: PAM_USER not set")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "oiaf-pam-helper: not implemented (user=%s service=%s rhost=%s tty=%s)\n", username, service, rhost, tty)
	os.Exit(1)
}
