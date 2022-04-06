#!/bin/bash
# Copyright (c) 2020 Gitpod GmbH. All rights reserved.
# Licensed under the GNU Affero General Public License (AGPL).
# See License-AGPL.txt in the project root for license information.

set -euo pipefail

DOCKER_VERSION=20.10.14
DOCKER_COMPOSE_VERSION=1.29.2
RUNC_VERSION=v1.1.0

curl -o docker.tgz      -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz
curl -o docker-compose  -fsSL https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-Linux-x86_64
curl -o runc            -fsSL https://github.com/opencontainers/runc/releases/download/${RUNC_VERSION}/runc.amd64
