# Thesis

## Generating Alerts
Alert generator script is created, tools might be swapped around and the target repo needs to be renamed before running. The script will run the following tools:
- Semgrep (code patterns)
- Trivy (dependencies + secrets)
- OWASP (dependencies)

## Script Archetecture
Raw tool outputs
   ↓
Tool-specific parsers
   ↓
Common normalized alert objects
   ↓
Enrichment / metrics
   ↓
Deduplication
   ↓
Merged output + summary report

## Current architecture
project/
├── main.py
├── alert_model.py
├── parsers/
│   ├── __init__.py
│   ├── trivy_parser.py
│   ├── owasp_parser.py
│   └── semgrep_parser.py
├── aggregator.py
├── deduplicator.py
└── statistics.py

## File Responsibilities
main.py: orchestrates the whole workflow
alert_model.py: defines the shared alert structure
parsers/*.py: convert raw tool JSON into normalized alerts
aggregator.py: combines all parsed alerts into one collection
deduplicator.py: detects and merges duplicate alerts
statistics.py: measures alert counts before and after deduplication

## Flow
main.py
  -> tells each parser to parse its own tool output

trivy_parser.py / owasp_parser.py / semgrep_parser.py
  -> each return normalized Alert objects to main.py

main.py
  -> sends all alerts to aggregator.py

aggregator.py
  -> combines all alerts into one list and returns it

main.py
  -> sends combined raw alerts to statistics.py

statistics.py
  -> calculates pre-dedup stats and returns them

main.py
  -> sends raw alerts to deduplicator.py

deduplicator.py
  -> merges duplicates and returns deduplicated alerts

main.py
  -> sends deduplicated alerts to statistics.py

statistics.py
  -> calculates post-dedup stats and returns them

main.py
  -> writes final JSON outputs and prints summary