// Copyright (c) 2021 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

package image_builder_mk3

import (
	"fmt"

	"github.com/gitpod-io/gitpod/installer/pkg/common"

	certmanagerv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func tlssecret(ctx *common.RenderContext) ([]runtime.Object, error) {
	return []runtime.Object{
		&certmanagerv1.Certificate{
			TypeMeta: common.TypeMetaCertificate,
			ObjectMeta: metav1.ObjectMeta{
				Name:      TLSSecretName,
				Namespace: ctx.Namespace,
				Labels:    common.DefaultLabels(Component),
			},
			Spec: certmanagerv1.CertificateSpec{
				Duration:   common.InternalCertDuration,
				SecretName: TLSSecretName,
				DNSNames: []string{
					fmt.Sprintf("gitpod.%s", ctx.Namespace),
					fmt.Sprintf("%s.%s.svc", Component, ctx.Namespace),
					fmt.Sprintf("%s.%s.svc.cluster.local", Component, ctx.Namespace),
					Component,
				},
				IssuerRef: cmmeta.ObjectReference{
					Name:  common.CertManagerCAIssuer,
					Kind:  "Issuer",
					Group: "cert-manager.io",
				},
				SecretTemplate: &certmanagerv1.CertificateSecretTemplate{
					Labels: common.DefaultLabels(Component),
				},
			},
		},
	}, nil

	// serverAltNames := []string{
	// 	fmt.Sprintf("%s.%s.svc", Component, ctx.Namespace),
	// 	fmt.Sprintf("%s.%s.svc.cluster.local", Component, ctx.Namespace),
	// 	Component,
	// 	fmt.Sprintf("%s-dev", Component),
	// }
	// clientAltNames := []string{
	// 	common.WSManagerComponent,
	// 	common.ServerComponent,
	// 	Component,
	// }

	// issuer := common.CertManagerCAIssuer

	// return []runtime.Object{
	// 	&certmanagerv1.Certificate{
	// 		TypeMeta: common.TypeMetaCertificate,
	// 		ObjectMeta: metav1.ObjectMeta{
	// 			Name:      TLSSecretNameSecret,
	// 			Namespace: ctx.Namespace,
	// 			Labels:    common.DefaultLabels(Component),
	// 		},
	// 		Spec: certmanagerv1.CertificateSpec{
	// 			Duration:   common.InternalCertDuration,
	// 			SecretName: TLSSecretNameSecret,
	// 			DNSNames:   serverAltNames,
	// 			IssuerRef: cmmeta.ObjectReference{
	// 				Name:  issuer,
	// 				Kind:  "Issuer",
	// 				Group: "cert-manager.io",
	// 			},
	// 			SecretTemplate: &certmanagerv1.CertificateSecretTemplate{
	// 				Labels: common.DefaultLabels(Component),
	// 			},
	// 		},
	// 	},
	// 	&certmanagerv1.Certificate{
	// 		TypeMeta: common.TypeMetaCertificate,
	// 		ObjectMeta: metav1.ObjectMeta{
	// 			Name:      Component,
	// 			Namespace: ctx.Namespace,
	// 			Labels:    common.DefaultLabels(Component),
	// 		},
	// 		Spec: certmanagerv1.CertificateSpec{
	// 			Duration:   common.InternalCertDuration,
	// 			SecretName: TLSSecretNameClient,
	// 			DNSNames:   clientAltNames,
	// 			IssuerRef: cmmeta.ObjectReference{
	// 				Name:  issuer,
	// 				Kind:  "Issuer",
	// 				Group: "cert-manager.io",
	// 			},
	// 			SecretTemplate: &certmanagerv1.CertificateSecretTemplate{
	// 				Labels: common.DefaultLabels(Component),
	// 			},
	// 		},
	// 	},
	// }, nil
}
