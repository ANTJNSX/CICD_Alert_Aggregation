#!/bin/bash
set -e

TARGET_REPO="${1:-Targets/WebGoat}"
REPO_NAME="$(basename "$TARGET_REPO")"
OUTPUT_DIR="ScanOutputs/$REPO_NAME"

mkdir -p "$OUTPUT_DIR"

echo "Running scans for: $REPO_NAME"
echo "Target repo: $TARGET_REPO"
echo "Output directory: $OUTPUT_DIR"
echo ""

echo "Running Semgrep (source-code findings)..."
docker run --rm \
  -v "$PWD/$TARGET_REPO:/src" \
  -v "$PWD/$OUTPUT_DIR:/out" \
  returntocorp/semgrep \
  semgrep --config=p/security-audit --json --output /out/${REPO_NAME}-semgrep.json /src

echo ""
echo "Running Trivy (dependency/filesystem findings)..."
docker run --rm \
  -v "$PWD/$TARGET_REPO:/src" \
  -v "$PWD/$OUTPUT_DIR:/out" \
  aquasec/trivy fs \
  --format json \
  --output /out/${REPO_NAME}-trivy.json \
  /src

echo ""
echo "Running OWASP Dependency-Check (dependency CVEs)..."
docker run --rm \
  -v "$PWD/$TARGET_REPO:/src" \
  -v "$PWD/$OUTPUT_DIR:/report" \
  owasp/dependency-check:latest \
  --scan /src \
  --format JSON \
  --out /report \
  --project "$REPO_NAME"

# Move the generated report to a consistent name
if [ -f "$OUTPUT_DIR/dependency-check-report.json" ]; then
  mv "$OUTPUT_DIR/dependency-check-report.json" "$OUTPUT_DIR/${REPO_NAME}-dependency-check.json"
fi

echo ""
echo "All scans complete."
echo "Results in $OUTPUT_DIR:"
ls -lh "$OUTPUT_DIR"