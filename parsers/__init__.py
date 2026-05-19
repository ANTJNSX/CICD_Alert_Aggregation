from parsers.trivy_parser import parse_trivy
from parsers.owasp_parser import parse_owasp
from parsers.semgrep_parser import parse_semgrep
from parsers.snyk_parser import parse_snyk

PARSER_REGISTRY = {
    "trivy": parse_trivy,
    "owasp": parse_owasp,
    "semgrep": parse_semgrep,
    "snyk": parse_snyk,
}
