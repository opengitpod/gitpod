// Copyright (c) 2022 Gitpod GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

package registry_credential

import (
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"

	"github.com/gitpod-io/gitpod/installer/pkg/common"
)

func cronjob(ctx *common.RenderContext) ([]runtime.Object, error) {
	objectMeta := metav1.ObjectMeta{
		Name:      Component,
		Namespace: ctx.Namespace,
		Labels:    common.DefaultLabels(Component),
	}

	return []runtime.Object{
		&batchv1.CronJob{
			TypeMeta:   common.TypeMetaBatchCronJob,
			ObjectMeta: objectMeta,
			Spec: batchv1.CronJobSpec{
				Schedule:                   CronSchedule,
				SuccessfulJobsHistoryLimit: pointer.Int32(1),
				FailedJobsHistoryLimit:     pointer.Int32(10),
				ConcurrencyPolicy:          batchv1.ReplaceConcurrent,
				JobTemplate: batchv1.JobTemplateSpec{
					ObjectMeta: objectMeta,
					Spec: batchv1.JobSpec{
						BackoffLimit: pointer.Int32(10),
						Template: v1.PodTemplateSpec{
							ObjectMeta: objectMeta,
							Spec: v1.PodSpec{
								RestartPolicy:      v1.RestartPolicyOnFailure,
								ServiceAccountName: Component,
								Containers: []v1.Container{
									{
										Name:            Component,
										Image:           "jenting/aws-iam-credential-rotate",
										ImagePullPolicy: v1.PullIfNotPresent,
										Command:         []string{"/aws-iam-credential-rotate", "ecr-update"},
										SecurityContext: &v1.SecurityContext{
											AllowPrivilegeEscalation: pointer.Bool(false),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}, nil
}
