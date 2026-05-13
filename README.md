# Thesis

## Generating Alerts
Alert generator script is created, tools might be swapped around and the target repo needs to be renamed before running. The script will run the following tools:
- Semgrep (code patterns)
- Trivy (dependencies + secrets)
- Dependency-Check (dependency CVEs)
- OSV-Scanner (dependency vulnerabilities)
- Gitleaks (secrets)

Next step will be to use the outputs of the tools and aggregate them...
