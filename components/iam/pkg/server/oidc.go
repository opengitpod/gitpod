// Copyright (c) 2022 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gitpod-io/gitpod/common-go/log"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OAuth2Result struct {
	OAuth2Token *oauth2.Token
	Redirect    string
}

type OIDCClientConfig struct {
	OAuth2Config *oauth2.Config
	OIDCConfig   *oidc.Config
}

type OIDCClient struct {
	Verifier *oidc.IDTokenVerifier
	Config   *OIDCClientConfig
}

func (client *OIDCClient) initiateFlow() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		log.Debug("initiateFlow")

		state, err := randString(32)
		if err != nil {
			http.Error(rw, "failed to initiate", http.StatusInternalServerError)
			return
		}

		nonce, err := randString(32)
		if err != nil {
			http.Error(rw, "failed to initiate", http.StatusInternalServerError)
			return
		}

		setCallbackCookie(rw, r, stateCookieName, state)
		setCallbackCookie(rw, r, nonceCookieName, nonce)

		http.Redirect(rw, r, client.Config.OAuth2Config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusTemporaryRedirect)
	})
}

const (
	stateCookieName = "state"
	nonceCookieName = "nonce"
)

func randString(size int) (string, error) {
	log.Debug("randString")
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(rw http.ResponseWriter, r *http.Request, name string, value string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(10 * time.Minute.Seconds()),
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
	}
	http.SetCookie(rw, cookie)
}

// Client config middleware
func (client *OIDCClient) configAware(config OIDCClientConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		log.Trace("configAware")

		// TODO(at) ensure a correct config is injected; it needs to be match the request
		// [ ] check state param
		// [ ] check state cookie

		ctx := context.WithValue(r.Context(), keyOIDCClientConfig{}, config)
		next.ServeHTTP(rw, r.WithContext(ctx))
	})
}

type keyOIDCClientConfig struct{}

// OAuth2 middleware
func (client *OIDCClient) handleOAuth2(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		log.Trace("handleOAuth2")
		ctx := r.Context()
		config, ok := ctx.Value(keyOIDCClientConfig{}).(OIDCClientConfig)
		if !ok {
			http.Error(rw, "config not found", http.StatusInternalServerError)
			return
		}

		stateCookie, err := r.Cookie(stateCookieName)
		stateParam := r.URL.Query().Get("state")
		if err != nil {
			http.Error(rw, "state cookie not found", http.StatusBadRequest)
			return
		}
		if stateParam == "" {
			http.Error(rw, "state param not found", http.StatusBadRequest)
			return
		}
		if stateParam != stateCookie.Value {
			http.Error(rw, "state did not match", http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")

		if code == "" {
			http.Error(rw, "code param not found", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.OAuth2Config.Exchange(ctx, code)
		if err != nil {
			http.Error(rw, "failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		ctx = context.WithValue(ctx, keyOAuth2Result{}, OAuth2Result{
			OAuth2Token: oauth2Token,
		})

		next.ServeHTTP(rw, r.WithContext(ctx))
	})
}

type keyOAuth2Result struct{}

// OIDC handler
func (client *OIDCClient) handleOIDC() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		log.Trace("handleOIDC")

		ctx := r.Context()
		// config, ok := ctx.Value(keyOIDCClientConfig{}).(OIDCClientConfig)
		// if !ok {
		// 	http.Error(rw, "config not found", http.StatusInternalServerError)
		// 	return
		// }
		oauth2Result, ok := ctx.Value(keyOAuth2Result{}).(OAuth2Result)
		if !ok {
			http.Error(rw, "OIDC precondition failure", http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := oauth2Result.OAuth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(rw, "id_token not found", http.StatusInternalServerError)
			return
		}

		idToken, err := client.Verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(rw, "failed to verify id_token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		nonce, err := r.Cookie(nonceCookieName)
		if err != nil {
			http.Error(rw, "nonce not found", http.StatusBadRequest)
			return
		}
		if idToken.Nonce != nonce.Value {
			http.Error(rw, "nonce did not match", http.StatusBadRequest)
			return
		}

		// TODO(at) add redirect

		oauth2Result.OAuth2Token.AccessToken = "*** REDACTED ***"

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims string
		}{oauth2Result.OAuth2Token, rawIDToken}

		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = rw.Write(data)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
	})
}
