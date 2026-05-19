#!/usr/bin/env bash

set -euo pipefail

# Hardcoded target directory to scan.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${ROOT_DIR}/Targets/WebGoat"
OUTPUT_DIR="${ROOT_DIR}/ScanOutputs/WebGoat"
OWASP_DATA_DIR="${ROOT_DIR}/.cache/dependency-check"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

SEMGREP_OUTPUT="${OUTPUT_DIR}/semgrep.json"
TRIVY_OUTPUT="${OUTPUT_DIR}/trivy.json"
OWASP_OUTPUT="${OUTPUT_DIR}/dependency-check-report.json"
SNYK_OUTPUT="${OUTPUT_DIR}/snyk.json"

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Error: '$1' is required but not installed." >&2
		exit 1
	fi
}

ensure_writable_dir() {
	local dir="$1"
	if [[ -w "${dir}" ]]; then
		return 0
	fi

	echo "WARN: ${dir} is not writable by uid=${HOST_UID}; attempting ownership fix via Docker." >&2
	docker run --rm \
		-v "${dir}:/fix" \
		alpine:3.20 \
		chown -R "${HOST_UID}:${HOST_GID}" /fix >/dev/null

	if [[ ! -w "${dir}" ]]; then
		echo "Error: ${dir} is still not writable. Fix ownership and rerun." >&2
		exit 1
	fi
}

echo "==> Preparing scan paths"
if [[ ! -d "${TARGET_DIR}" ]]; then
	echo "Error: hardcoded target directory not found: ${TARGET_DIR}" >&2
	exit 1
fi
mkdir -p "${OUTPUT_DIR}"
mkdir -p "${OWASP_DATA_DIR}"

require_cmd docker
ensure_writable_dir "${OUTPUT_DIR}"
ensure_writable_dir "${OWASP_DATA_DIR}"

echo "==> Running Semgrep scan"
docker run --rm \
	--user "${HOST_UID}:${HOST_GID}" \
	-v "${TARGET_DIR}:/src" \
	-v "${OUTPUT_DIR}:/out" \
	semgrep/semgrep:latest \
	semgrep scan --config auto --json --output /out/semgrep.json /src

echo "==> Running Trivy filesystem scan"
docker run --rm \
	--user "${HOST_UID}:${HOST_GID}" \
	-v "${TARGET_DIR}:/project" \
	-v "${OUTPUT_DIR}:/out" \
	aquasec/trivy:latest \
	fs --scanners vuln,misconfig,secret --format json --output /out/trivy.json /project

echo "==> Running OWASP Dependency-Check scan"
OWASP_ARGS=(--project "WebGoat" --scan /src --format JSON --out /report)
if [[ -n "${NVD_API_KEY:-}" ]]; then
	OWASP_ARGS+=(--nvdApiKey "${NVD_API_KEY}")
fi

owasp_exit=0
if docker run --rm \
	--user "${HOST_UID}:${HOST_GID}" \
	-v "${TARGET_DIR}:/src" \
	-v "${OUTPUT_DIR}:/report" \
	-v "${OWASP_DATA_DIR}:/usr/share/dependency-check/data" \
	owasp/dependency-check:latest \
	"${OWASP_ARGS[@]}"; then
	owasp_exit=0
else
	owasp_exit=$?
	echo "WARN: Dependency-Check update failed; retrying with cached data (--noupdate)." >&2
	if docker run --rm \
		--user "${HOST_UID}:${HOST_GID}" \
		-v "${TARGET_DIR}:/src" \
		-v "${OUTPUT_DIR}:/report" \
		-v "${OWASP_DATA_DIR}:/usr/share/dependency-check/data" \
		owasp/dependency-check:latest \
		"${OWASP_ARGS[@]}" --noupdate; then
		owasp_exit=0
	else
		owasp_exit=$?
	fi
fi

if [[ ${owasp_exit} -ne 0 ]]; then
	if [[ -s "${OWASP_OUTPUT}" ]]; then
		echo "WARN: Dependency-Check exited non-zero (${owasp_exit}) but report exists at ${OWASP_OUTPUT}; continuing." >&2
	else
		echo "Error: Dependency-Check failed and no report was generated." >&2
		exit ${owasp_exit}
	fi
fi

if [[ -n "${SNYK_TOKEN:-}" ]]; then
	echo "==> Running Snyk Open Source scan"
	snyk_exit=0
	if docker run --rm \
		--user "${HOST_UID}:${HOST_GID}" \
		-e SNYK_TOKEN="${SNYK_TOKEN}" \
		-v "${TARGET_DIR}:/project" \
		-v "${OUTPUT_DIR}:/out" \
		-w /project \
		snyk/snyk-cli:latest \
		test --all-projects --json-file-output=/out/snyk.json; then
		snyk_exit=0
	else
    echo 'Snyk token not found' >&2
		snyk_exit=$?
	fi

	# Snyk exits non-zero when vulnerabilities are found; keep the report if it exists.
	if [[ ${snyk_exit} -ne 0 && ! -s "${SNYK_OUTPUT}" ]]; then
		echo "Error: Snyk scan failed and no report was generated." >&2
		exit ${snyk_exit}
	fi
	if [[ ${snyk_exit} -ne 0 && -s "${SNYK_OUTPUT}" ]]; then
		echo "WARN: Snyk exited non-zero (${snyk_exit}) but report exists at ${SNYK_OUTPUT}; continuing." >&2
	fi
else
	echo "WARN: SNYK_TOKEN not set; skipping Snyk scan." >&2
fi

echo
echo "==> Scan complete. Output files:"
echo "- ${SEMGREP_OUTPUT}"
echo "- ${TRIVY_OUTPUT}"
echo "- ${OWASP_OUTPUT}"
if [[ -s "${SNYK_OUTPUT}" ]]; then
	echo "- ${SNYK_OUTPUT}"
fi

echo
echo "==> File sizes:"
if [[ -s "${SNYK_OUTPUT}" ]]; then
	ls -lh "${SEMGREP_OUTPUT}" "${TRIVY_OUTPUT}" "${OWASP_OUTPUT}" "${SNYK_OUTPUT}"
else
	ls -lh "${SEMGREP_OUTPUT}" "${TRIVY_OUTPUT}" "${OWASP_OUTPUT}"
fi
