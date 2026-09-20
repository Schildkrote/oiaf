// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/Schildkrote/oiaf/core/internal/types"
)

type contextKey string

const TokenContextKey contextKey = "auth_token"

func Middleware(auth *Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}
			tokenStr := strings.TrimPrefix(header, "Bearer ")
			if tokenStr == header {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}
			tok, err := auth.Validate(r.Context(), tokenStr)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), TokenContextKey, tok)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireRole(roles ...types.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, ok := r.Context().Value(TokenContextKey).(*types.AuthToken)
			if !ok {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			for _, role := range roles {
				if tok.Role == role {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		})
	}
}

func TokenFromContext(ctx context.Context) *types.AuthToken {
	tok, _ := ctx.Value(TokenContextKey).(*types.AuthToken)
	return tok
}
