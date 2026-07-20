#!/usr/bin/env bash
# Install the Nyalai pre-push hook into this local git repository.
# Run once after clone : bash scripts/install-hooks.sh
set -eu
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK_TARGET="${REPO_ROOT}/.git/hooks/pre-push"
HOOK_SOURCE="${REPO_ROOT}/scripts/git-pre-push-nyalai.sh"
if [[ ! -d "${REPO_ROOT}/.git" ]]; then
    echo "[install-hooks] ERROR : ${REPO_ROOT} is not a git repository. Run git init first."
    exit 2
fi
if [[ ! -f "${HOOK_SOURCE}" ]]; then
    echo "[install-hooks] ERROR : hook source not found at ${HOOK_SOURCE}"
    exit 2
fi
cp "${HOOK_SOURCE}" "${HOOK_TARGET}"
chmod +x "${HOOK_TARGET}"
echo "[install-hooks] pre-push hook installed at ${HOOK_TARGET}"
echo "[install-hooks] Test : run 'git push' from any branch to trigger the hook."
