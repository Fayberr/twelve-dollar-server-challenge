#!/usr/bin/env bash
set -euo pipefail
apt-get update
apt-get install -y build-essential curl ca-certificates libssl-dev python3 unzip
