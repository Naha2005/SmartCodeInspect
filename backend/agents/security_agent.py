import ast
import logging
import re
from typing import List, Optional

try:
    from analyzers.rules.base_rule import Finding
    from analyzers.rules.python_rules import PythonSecurityVisitor
    from analyzers.rules.java_rules import JavaSecurityAnalyzer
except ImportError:
    try:
        from backend.analyzers.rules.base_rule import Finding
        from backend.analyzers.rules.python_rules import PythonSecurityVisitor
        from backend.analyzers.rules.java_rules import JavaSecurityAnalyzer
    except ImportError:
        from ..analyzers.rules.base_rule import Finding
        from ..analyzers.rules.python_rules import PythonSecurityVisitor
        from ..analyzers.rules.java_rules import JavaSecurityAnalyzer


logger = logging.getLogger(__name__)


# Precise CWE mappings for OWASP rules (no vague or invented identifiers)
CWE_MAPPING = {
    "SEC-PY-001": "CWE-95",
    "SEC-PY-002": "CWE-78",
    "SEC-PY-003": "CWE-89",
    "SEC-PY-004": "CWE-798",
    "SEC-PY-005": "CWE-502",
    "SEC-PY-006": "CWE-327",
    "SEC-PY-007": "CWE-22",
    "SEC-PY-008": "CWE-918",
    "SEC-JV-001": "CWE-89",
    "SEC-JV-002": "CWE-78",
    "SEC-JV-003": "CWE-798",
    "SEC-JV-004": "CWE-502",
    "SEC-JV-005": "CWE-327",
    "SEC-JV-006": "CWE-22",
    "SEC-JV-007": "CWE-611",
}

# Standard OWASP Top 10 (2021) categories
OWASP_CATEGORY_MAPPING = {
    "SEC-PY-001": "A03:2021 – Injection",
    "SEC-PY-002": "A03:2021 – Injection",
    "SEC-PY-003": "A03:2021 – Injection",
    "SEC-PY-004": "A07:2021 – Identification and Authentication Failures",
    "SEC-PY-005": "A08:2021 – Software and Data Integrity Failures",
    "SEC-PY-006": "A02:2021 – Cryptographic Failures",
    "SEC-PY-007": "A01:2021 – Broken Access Control",
    "SEC-PY-008": "A10:2021 – Server-Side Request Forgery (SSRF)",
    "SEC-JV-001": "A03:2021 – Injection",
    "SEC-JV-002": "A03:2021 – Injection",
    "SEC-JV-003": "A07:2021 – Identification and Authentication Failures",
    "SEC-JV-004": "A08:2021 – Software and Data Integrity Failures",
    "SEC-JV-005": "A02:2021 – Cryptographic Failures",
    "SEC-JV-006": "A01:2021 – Broken Access Control",
    "SEC-JV-007": "A05:2021 – Security Misconfiguration",
}


def _severity_score(severity: str) -> float:
    """Provide a fallback score when a rule has no valid score."""
    return {
        "Critical": 9.5,
        "High": 7.5,
        "Medium": 5.0,
        "Low": 2.5,
        "Informational": 1.0,
    }.get(severity, 1.0)


def _make_finding(**kwargs) -> Finding:
    """Create a Finding using the existing project model."""
    return Finding(**kwargs)


def _call_name(node: ast.Call) -> str:
    """Return the dotted name of a Python function call."""
    parts = []
    current = node.func

    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value

    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))

    return ""


class PythonAdvancedSecurityVisitor(ast.NodeVisitor):
    """
    Additional heuristic checks for Python path traversal and SSRF.

    Dynamic input is treated as a potential risk, not proof of
    exploitability. This visitor does not perform full taint analysis.
    """

    URL_CALLS = {
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "requests.patch",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.delete",
        "httpx.patch",
        "httpx.request",
        "urllib.request.urlopen",
    }

    FILE_CALLS = {
        "open",
        "io.open",
        "os.open",
        "os.path.join",
        "pathlib.Path",
        "Path",
    }

    def __init__(self, source_lines: List[str]):
        super().__init__()
        self.source_lines = source_lines
        self.findings: List[Finding] = []

    def _snippet(self, line: int) -> str:
        if 1 <= line <= len(self.source_lines):
            return self.source_lines[line - 1].strip()
        return ""

    @staticmethod
    def _is_dynamic(node: ast.AST) -> bool:
        """
        Conservative heuristic for expressions that may depend
        on runtime input. It does not establish user control.
        """
        return isinstance(
            node,
            (
                ast.Name,
                ast.JoinedStr,
                ast.BinOp,
                ast.Call,
                ast.Attribute,
                ast.Subscript,
            ),
        )

    def visit_Call(self, node: ast.Call):
        name = _call_name(node)
        line = getattr(node, "lineno", 1)
        column = getattr(node, "col_offset", 0)
        snippet = self._snippet(line)

        # SEC-PY-007: Potential path traversal.
        # Joining a path is not inherently vulnerable; report only
        # as a potential issue when the path contains dynamic input.
        if name in self.FILE_CALLS and node.args:
            dynamic_path = any(
                self._is_dynamic(arg)
                for arg in node.args
            )

            traversal_literal = any(
                isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and ("../" in arg.value or "..\\" in arg.value)
                for arg in node.args
            )

            if dynamic_path or traversal_literal:
                self.findings.append(
                    _make_finding(
                        rule_id="SEC-PY-007",
                        title="Potential Path Traversal",
                        description=(
                            f"Call to '{name}()' uses a potentially "
                            "dynamic filesystem path. Verify that the "
                            "resolved path stays inside the intended "
                            "directory."
                        ),
                        severity="High",
                        severity_score=7.8,
                        language="python",
                        line=line,
                        column=column,
                        evidence=snippet,
                        risk_explanation=(
                            "An attacker-controlled path may escape an "
                            "intended directory if input is not validated "
                            "and containment is not enforced."
                        ),
                        mitigation=(
                            "Resolve the target path and verify that it "
                            "is contained within a trusted base directory. "
                            "Do not rely on string-prefix checks alone; "
                            "use path-aware containment validation."
                        ),
                        owasp_references=[
                            "https://cwe.mitre.org/data/definitions/22.html",
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                        ],
                        confidence="Medium",
                        owasp_category="A01:2021 – Broken Access Control",
                        category="Security Vulnerability",
                        agent="Security Vulnerability Agent",
                        cwe_id="CWE-22",
                    )
                )

        # SEC-PY-008: Potential SSRF.
        if name in self.URL_CALLS and node.args:
            url_arg = node.args[0]

            if self._is_dynamic(url_arg):
                self.findings.append(
                    _make_finding(
                        rule_id="SEC-PY-008",
                        title="Potential Server-Side Request Forgery",
                        description=(
                            f"Call to '{name}()' uses a non-literal URL. "
                            "Confirm that destinations are validated "
                            "against an explicit allowlist."
                        ),
                        severity="High",
                        severity_score=8.0,
                        language="python",
                        line=line,
                        column=column,
                        evidence=snippet,
                        risk_explanation=(
                            "If an attacker can control the destination, "
                            "the server may be induced to request internal "
                            "services or restricted network addresses."
                        ),
                        mitigation=(
                            "Allow only approved destination hosts, validate "
                            "resolved IP addresses, handle redirects safely, "
                            "and block loopback, private and link-local "
                            "destinations where appropriate."
                        ),
                        owasp_references=[
                            "https://cwe.mitre.org/data/definitions/918.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                        ],
                        confidence="Medium",
                        owasp_category="A10:2021 – Server-Side Request Forgery (SSRF)",
                        category="Security Vulnerability",
                        agent="Security Vulnerability Agent",
                        cwe_id="CWE-918",
                    )
                )

        self.generic_visit(node)


class JavaAdvancedSecurityScanner:
    """
    Additional heuristic checks for Java path traversal and XXE.

    Java source scanning uses regular expressions and is not a
    replacement for a Java parser or full data-flow analysis.
    """

    PATH_CONSTRUCTOR_RE = re.compile(
        r"\b(?:new\s+(?:[A-Za-z0-9_.]+\.)?(?:File|FileInputStream|FileOutputStream|"
        r"FileReader|FileWriter)|(?:[A-Za-z0-9_.]+\.)?(?:Paths\.get|Path\.of))\s*\(",
        re.IGNORECASE,
    )

    XML_FACTORY_RE = re.compile(
        r"\b(?:DocumentBuilderFactory|SAXParserFactory|"
        r"XMLInputFactory)\s*\.\s*newInstance\s*\(",
    )

    def __init__(self, source_code: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.findings: List[Finding] = []

    def _snippet(self, line: int) -> str:
        if 1 <= line <= len(self.source_lines):
            return self.source_lines[line - 1].strip()
        return ""

    @staticmethod
    def _remove_simple_comments(line: str) -> str:
        """
        Skip obvious comment lines. This is intentionally not a
        full Java lexer and does not remove inline comments safely
        when comment markers occur inside string literals.
        """
        stripped = line.strip()

        if stripped.startswith("//") or stripped.startswith("*"):
            return ""

        return line

    def scan(self) -> List[Finding]:
        self.findings.clear()

        for line_no, original_line in enumerate(
            self.source_lines,
            start=1,
        ):
            line = self._remove_simple_comments(original_line)

            if not line.strip():
                continue

            stripped = line.strip()

            # SEC-JV-006: Potential path traversal.
            if self.PATH_CONSTRUCTOR_RE.search(line):
                # Constructor use alone is not proof of a vulnerability.
                # Lower confidence because regex cannot establish data flow.
                # Check for traversal literals, concatenation, or dynamic variables
                ctor_match = re.search(
                    r"\b(?:new\s+(?:[A-Za-z0-9_.]+\.)?(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter)|(?:[A-Za-z0-9_.]+\.)?(?:Paths\.get|Path\.of))\s*\(([^;]+)\)",
                    line,
                    re.IGNORECASE,
                )
                has_dynamic_arg = False
                if ctor_match:
                    args_str = ctor_match.group(1).strip()
                    if ".." in args_str:
                        has_dynamic_arg = True
                    elif "+" in args_str or re.search(
                        r"\b[A-Za-z_][A-Za-z0-9_]*\b",
                        re.sub(r'"[^"]*"', "", args_str),
                    ):
                        has_dynamic_arg = True
                elif ".." in line or re.search(
                    r"\b[A-Za-z0-9_]*(?:request|parameter|input|user|path|filename|file)[A-Za-z0-9_]*\b",
                    line,
                    re.IGNORECASE,
                ):
                    has_dynamic_arg = True

                if has_dynamic_arg:
                    self.findings.append(
                        _make_finding(
                            rule_id="SEC-JV-006",
                            title="Potential Java Path Traversal",
                            description=(
                                "A file or stream constructor appears to "
                                "use a potentially externally controlled "
                                "value. Validate the resolved path before "
                                "accessing the filesystem."
                            ),
                            severity="High",
                            severity_score=7.8,
                            language="java",
                            line=line_no,
                            column=0,
                            evidence=stripped,
                            risk_explanation=(
                                "An unsafe path can allow access outside "
                                "the intended filesystem directory."
                            ),
                            mitigation=(
                                "Resolve the target path and verify it "
                                "remains within an explicitly trusted base "
                                "directory before opening the file."
                            ),
                            owasp_references=[
                                "https://cwe.mitre.org/data/definitions/22.html",
                                "https://owasp.org/www-community/attacks/Path_Traversal",
                            ],
                            confidence="Low",
                            owasp_category="A01:2021 – Broken Access Control",
                            category="Security Vulnerability",
                            agent="Security Vulnerability Agent",
                            cwe_id="CWE-22",
                        )
                    )

        # SEC-JV-007: Potential XXE.
        # Examine parser initialization and nearby configuration.
        # This remains heuristic; it cannot reliably prove that a parser
        # is safe or unsafe across all Java XML APIs.
        for index, original_line in enumerate(
            self.source_lines
        ):
            line = self._remove_simple_comments(original_line)

            if not self.XML_FACTORY_RE.search(line):
                continue

            line_no = index + 1
            context_start = max(0, index - 3)
            context_end = min(
                len(self.source_lines),
                index + 16,
            )
            context = "\n".join(
                self.source_lines[context_start:context_end]
            )

            protection_markers = (
                "disallow-doctype-decl",
                "external-general-entities",
                "external-parameter-entities",
                "ACCESS_EXTERNAL_DTD",
                "ACCESS_EXTERNAL_SCHEMA",
                "XMLInputFactory.SUPPORT_DTD",
                "IS_SUPPORTING_EXTERNAL_ENTITIES",
            )

            has_protection_marker = any(
                marker in context
                for marker in protection_markers
            )

            if has_protection_marker:
                continue

            self.findings.append(
                _make_finding(
                    rule_id="SEC-JV-007",
                    title="Potential Insecure XML Parser Configuration",
                    description=(
                        "An XML parser factory is initialized without "
                        "an obvious XXE protection setting near the "
                        "initialization. Review the complete parser "
                        "configuration and actual parsing flow."
                    ),
                    severity="High",
                    severity_score=7.5,
                    language="java",
                    line=line_no,
                    column=0,
                    evidence=self._snippet(line_no),
                    risk_explanation=(
                        "Unsafe XML parser configuration can permit "
                        "external entity processing, potentially exposing "
                        "local files or triggering requests to other systems."
                    ),
                    mitigation=(
                        "Explicitly disable DTD and external entity "
                        "processing using the security settings appropriate "
                        "to the XML API in use. Fail safely if required "
                        "security features cannot be configured."
                    ),
                    owasp_references=[
                        "https://cwe.mitre.org/data/definitions/611.html",
                        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                    ],
                    confidence="Low",
                    owasp_category="A05:2021 – Security Misconfiguration",
                    category="Security Vulnerability",
                    agent="Security Vulnerability Agent",
                    cwe_id="CWE-611",
                )
            )

        return self.findings


class SecurityVulnerabilityAgent:
    """
    Coordinates existing Python and Java security rules with
    additional path-traversal, SSRF and XXE checks.

    Findings indicate potential issues and require validation.
    Submitted code is analyzed, never executed by this agent.
    """

    def __init__(self):
        self.name = "Security Vulnerability Agent"
        self.version = "1.1.0"

    def analyze(
        self,
        source_code: str,
        language: str,
        filename: Optional[str] = None,
    ) -> List[Finding]:
        if not isinstance(source_code, str) or not source_code.strip():
            return []

        if not isinstance(language, str):
            return []

        lang = language.strip().lower()

        if lang in ("python", "py", "python3"):
            lang = "python"
        elif lang in ("java", "jav"):
            lang = "java"
        else:
            logger.warning("Unsupported security scan language: %s", lang)
            return []

        try:
            if lang == "python":
                findings = self._analyze_python(source_code)
            else:
                findings = self._analyze_java(source_code)

        except Exception:
            # Log the internal exception for developers; don't leak
            # exception details or submitted source through API responses.
            logger.exception(
                "Security analysis failed for language %s.",
                lang,
            )
            raise

        for finding in findings:
            # Preserve the existing Finding model and normalize metadata.
            if hasattr(finding, "agent"):
                finding.agent = self.name

            if hasattr(finding, "category"):
                finding.category = "Security Vulnerability"

            rule_id = getattr(finding, "rule_id", "")
            cwe_id = CWE_MAPPING.get(rule_id)

            if hasattr(finding, "cwe_id"):
                existing = getattr(finding, "cwe_id", "")
                if not existing or existing == "CWE-General":
                    finding.cwe_id = cwe_id or ""

            if hasattr(finding, "owasp_category"):
                if not getattr(finding, "owasp_category", None):
                    finding.owasp_category = OWASP_CATEGORY_MAPPING.get(rule_id, "")

            score = getattr(finding, "severity_score", 0.0)

            try:
                score = float(score)
            except (TypeError, ValueError):
                score = 0.0

            if score <= 0.0 and hasattr(finding, "severity_score"):
                finding.severity_score = _severity_score(
                    getattr(finding, "severity", "Informational")
                )

        return findings

    def _analyze_python(
        self,
        source_code: str,
    ) -> List[Finding]:
        # Syntax validation should be reported by the existing validation
        # endpoint. Don't misrepresent a parse failure as a clean scan.
        try:
            parsed_ast = ast.parse(source_code)
        except SyntaxError as exc:
            logger.warning(
                "Python security analysis skipped due to syntax error "
                "at line %s.",
                exc.lineno,
            )
            return []

        source_lines = source_code.splitlines()
        findings: List[Finding] = []

        # Existing rules for SEC-PY-001 through SEC-PY-006.
        base_visitor = PythonSecurityVisitor(
            source_lines=source_lines,
        )
        base_visitor.visit(parsed_ast)
        findings.extend(base_visitor.findings)

        # Additional rules for SEC-PY-007 and SEC-PY-008.
        advanced_visitor = PythonAdvancedSecurityVisitor(
            source_lines=source_lines,
        )
        advanced_visitor.visit(parsed_ast)
        findings.extend(advanced_visitor.findings)

        return findings

    def _analyze_java(
        self,
        source_code: str,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Existing rules for SEC-JV-001 through SEC-JV-005.
        base_analyzer = JavaSecurityAnalyzer(source_code)
        findings.extend(base_analyzer.analyze())

        # Additional rules for SEC-JV-006 and SEC-JV-007.
        advanced_scanner = JavaAdvancedSecurityScanner(source_code)
        findings.extend(advanced_scanner.scan())

        return findings
