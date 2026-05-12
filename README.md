# Thesis

## Generating Alerts

### Trivy:
docker run --rm \
  -v "$PWD:/src" \
  returntocorp/semgrep \
  semgrep --config=p/security-audit --json --output /src/scan-outputs/semgrep.json /src

### Semgrep:
docker run --rm \
  -v "$PWD:/src" \
  returntocorp/semgrep \
  semgrep --config=p/security-audit --json --output /src/scan-outputs/semgrep.json /src


### OWASP:
docker run --rm \
  -v "$PWD:/src" \
  -v "$PWD/scan-outputs:/report" \
  owasp/dependency-check:latest \
  --scan /src \
  --format JSON \
  --format SARIF \
  --out /report

### GitLeaks(May not be needed):
docker run --rm \
  -v "$PWD:/repo" \
  zricethezav/gitleaks:latest \
  detect --source /repo --report-format json --report-path /repo/scan-outputs/gitleaks.json
