// Copyright (c) 2022 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License.AGPL.txt in the project root for license information.

package server

import (
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gitpod-io/gitpod/common-go/baseserver"
	"github.com/gitpod-io/gitpod/iam/pkg/config"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

func Start(logger *logrus.Entry, version string, cfg *config.ServiceConfig) error {
	logger.WithField("config", cfg).Info("starting IAM server.")

	logger.Logger.SetLevel(logrus.TraceLevel)

	srv, err := baseserver.New("iam",
		baseserver.WithLogger(logger),
		baseserver.WithConfig(cfg.Server),
		baseserver.WithVersion(version),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize IAM server: %w", err)
	}

	testConfig, err := ReadGoogleTestConfigFromFile(cfg.OIDCClientsConfigFile)
	if err != nil {
		return fmt.Errorf("failed to read test config: %w", err)
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, testConfig.Issuer)
	if err != nil {
		return fmt.Errorf("failed to initialize OIDC client server: %w", err)
	}

	oidcConfig := &oidc.Config{
		ClientID: testConfig.ClientID,
	}
	oauth2Config := &oauth2.Config{
		ClientID:     testConfig.ClientID,
		ClientSecret: testConfig.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  testConfig.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	oidcClientConfig := OIDCClientConfig{
		OAuth2Config: oauth2Config,
		OIDCConfig:   oidcConfig,
	}

	// This is just a prototype with a single client config + verifier
	verifier := provider.Verifier(oidcConfig)
	client := &OIDCClient{
		// TODO(at) replace single verifier with a provider to cache verifiers per issuer (as suggested in RFC)
		Verifier: verifier,
		Config:   &oidcClientConfig,
	}

	srv.HTTPMux().Handle("/oidc/start", client.initiateFlow())
	srv.HTTPMux().Handle("/oidc/callback", client.configAware(oidcClientConfig, client.handleOAuth2(client.handleOIDC())))

	if listenErr := srv.ListenAndServe(); listenErr != nil {
		return fmt.Errorf("failed to serve iam server: %w", err)
	}

	return nil
}
