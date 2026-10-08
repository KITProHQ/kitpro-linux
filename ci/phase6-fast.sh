#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

python -m unittest discover -s tests -v
python -m tools.worker_manifest validate-lock ci/worker-lock.json >/dev/null
python -m tools.check_tracked_secrets
git diff --check
