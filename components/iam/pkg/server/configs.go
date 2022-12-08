// Copyright (c) 2022 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

package server

import (
	"encoding/json"
	"fmt"
	"os"
)

type GoogleTestConfig struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RedirectURL  string `json:"redirectURL"`
}

func ReadGoogleTestConfigFromFile(path string) (GoogleTestConfig, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return GoogleTestConfig{}, fmt.Errorf("failed to read test config: %w", err)
	}

	var config GoogleTestConfig
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		return GoogleTestConfig{}, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return config, nil
}
