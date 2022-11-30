// Copyright (c) 2021 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

package wsmanager

import (
	"github.com/gitpod-io/gitpod/installer/pkg/common"
	"github.com/gitpod-io/gitpod/installer/pkg/config/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var Objects = func(ctx *common.RenderContext) ([]runtime.Object, error) {
	// Only deploy tls secret in webapp clusters.
	fs := []common.RenderFunc{
		tlssecret,
	}
	if ctx.Config.Kind != config.InstallationWebApp {
		fs = append(fs,
			configmap,
			deployment,
			networkpolicy,
			role,
			rolebinding,
			common.DefaultServiceAccount(Component),
			common.GenerateService(Component, []common.ServicePort{
				{
					Name:          RPCPortName,
					ContainerPort: RPCPort,
					ServicePort:   RPCPort,
				},
			}),
			unprivilegedRolebinding)
	}
	return common.CompositeRenderFunc(fs...)(ctx)
}
