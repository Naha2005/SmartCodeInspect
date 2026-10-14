import re
from typing import List
from .base_rule import Finding


class JavaSecurityAnalyzer:
    """
    Deterministic static security analyzer for Java source code.
    Inspects syntax patterns and semantic structures without executing any bytecode.
    """

    def __init__(self, source_code: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.findings: List[Finding] = []

    def _get_line_snippet(self, line_num: int) -> str:
        if 1 <= line_num <= len(self.source_lines):
            return self.source_lines[line_num - 1].strip()
        return ""

    def analyze(self) -> List[Finding]:
        self.findings.clear()

        # Rule SEC-JV-001: SQL Injection through query concatenation in execute calls
        # Matches: executeQuery("SELECT ... " + ...) or prepareStatement("..." + ...)
        sql_exec_pattern = re.compile(
            r'(\b(?:executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*["\'].*?["\']\s*\+)',
            re.IGNORECASE
        )

        # Also catch variable assignment SQL strings with concatenation
        # E.g.: String query = "SELECT * FROM users WHERE username = '" + user + "'";
        sql_assign_pattern = re.compile(
            r'\bString\s+\w+\s*=\s*["\'](?:SELECT|INSERT|UPDATE|DELETE|MERGE|CALL)\b.*?["\'].*?\+',
            re.IGNORECASE | re.DOTALL
        )

        # Rule SEC-JV-002: Dangerous command execution via Runtime.exec or ProcessBuilder
        runtime_exec_pattern = re.compile(
            r'(\bRuntime\.getRuntime\(\)\.exec\s*\()|(\bnew\s+ProcessBuilder\s*\()',
            re.IGNORECASE
        )

        # Rule SEC-JV-003: Hardcoded Credentials / Secrets
        # Covers: private static final String AWS_SECRET = "...", String password = "..."
        # Access modifiers are optional: private/public/protected, static, final
        secret_pattern = re.compile(
            r'(?:(?:private|public|protected|static|final)\s+){0,4}'
            r'(?:String|char\[\])\s+'
            r'([A-Za-z0-9_]*(?:password|passwd|apiKey|api_key|secret|privateKey|private_key|token|auth_token|credential|aws_secret|db_pass|db_password)[A-Za-z0-9_]*)'
            r'\s*=\s*["\']([^"\']{4,})["\']',
            re.IGNORECASE
        )

        # Rule SEC-JV-004: Insecure Deserialization via ObjectInputStream.readObject
        deserialization_pattern = re.compile(
            r'(\bnew\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\))'
        )

        # Rule SEC-JV-005: Weak Cryptographic Algorithms (MD5, SHA-1, DES)
        weak_crypto_pattern = re.compile(
            r'(\bMessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-?1)["\']\s*\))|(\bCipher\.getInstance\s*\(\s*["\'](?:DES|DESede|Blowfish)["\']\s*\))',
            re.IGNORECASE
        )

        for line_idx, line in enumerate(self.source_lines, start=1):
            stripped = line.strip()

            # Skip pure single-line comment lines
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            # SEC-JV-001: SQL Injection — direct execute call with concatenation
            if sql_exec_pattern.search(line):
                col_offset = max(0, line.find("execute"))
                self.findings.append(Finding(
                    rule_id="SEC-JV-001",
                    title="Potential SQL Injection via Dynamic Query Concatenation",
                    description="SQL query constructed by concatenating variables into statement execution or preparation method.",
                    severity="High",
                    language="java",
                    line=line_idx,
                    column=col_offset,
                    evidence=stripped,
                    risk_explanation="Concatenating external data into SQL queries allows attackers to manipulate query logic, bypass authentication, and exfiltrate database records.",
                    mitigation="Use PreparedStatement with parameterized '?' placeholders and set parameters using typed setter methods (e.g. setString, setInt).",
                    owasp_references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        "https://owasp.org/www-project-top-ten/2021/A03_Injection/"
                    ],
                    confidence="High",
                    owasp_category="A03:2021 – Injection"
                ))

            # SEC-JV-001: SQL Injection — variable assignment with SQL string + concatenation
            elif sql_assign_pattern.search(line):
                col_offset = max(0, line.find("String"))
                self.findings.append(Finding(
                    rule_id="SEC-JV-001",
                    title="Potential SQL Injection via Dynamic Query String Construction",
                    description="SQL query string built through string concatenation with user-controlled variables.",
                    severity="High",
                    language="java",
                    line=line_idx,
                    column=col_offset,
                    evidence=stripped,
                    risk_explanation="Concatenating external data into SQL queries allows attackers to manipulate query logic, bypass authentication, and exfiltrate database records.",
                    mitigation="Use PreparedStatement with parameterized '?' placeholders and set parameters using typed setter methods (e.g. setString, setInt).",
                    owasp_references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        "https://owasp.org/www-project-top-ten/2021/A03_Injection/"
                    ],
                    confidence="High",
                    owasp_category="A03:2021 – Injection"
                ))

            # SEC-JV-002: Command Injection
            if runtime_exec_pattern.search(line):
                col_offset = max(0, line.find("exec") if "exec" in line else line.find("ProcessBuilder"))
                self.findings.append(Finding(
                    rule_id="SEC-JV-002",
                    title="Dangerous Command Execution via Runtime.exec / ProcessBuilder",
                    description="Execution of system-level commands using Runtime.exec() or ProcessBuilder.",
                    severity="High",
                    language="java",
                    line=line_idx,
                    column=col_offset,
                    evidence=stripped,
                    risk_explanation="Direct system execution with external parameters permits OS Command Injection, granting adversaries arbitrary command execution on the host.",
                    mitigation="Avoid system command execution where possible. When strictly necessary, pass strictly validated commands as an array/List of arguments without passing command strings to a shell interpreter.",
                    owasp_references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/78.html"
                    ],
                    confidence="High",
                    owasp_category="A03:2021 – Injection"
                ))

            # SEC-JV-003: Hardcoded Credentials
            secret_match = secret_pattern.search(line)
            if secret_match:
                var_name = secret_match.group(1)
                val = secret_match.group(2)
                # Filter out obvious dummies
                if val.lower() not in ("none", "null", "false", "true", "dummy", "placeholder", "xxx"):
                    masked_evidence = re.sub(r'([\'"]).*?([\'"])', r'\1********\2', stripped)
                    col_offset = max(0, line.find(var_name))
                    self.findings.append(Finding(
                        rule_id="SEC-JV-003",
                        title=f"Hardcoded Credential or Secret in '{var_name}'",
                        description=f"Field or local variable '{var_name}' is assigned an inline plaintext string containing sensitive credential data.",
                        severity="High",
                        language="java",
                        line=line_idx,
                        column=col_offset,
                        evidence=masked_evidence,
                        risk_explanation="Hardcoded secrets in Java classes are easily extracted using decompilers (e.g. jadx, cfr) or leaked via source control repositories.",
                        mitigation="Externalize secrets to environment variables (System.getenv), a configuration vault, or a secure key store.",
                        owasp_references=[
                            "https://owasp.org/www-project-top-ten/2021/A07_Identification_and_Authentication_Failures/",
                            "https://cwe.mitre.org/data/definitions/798.html"
                        ],
                        confidence="High",
                        owasp_category="A07:2021 – Identification and Authentication Failures"
                    ))

            # SEC-JV-004: Insecure Deserialization
            if deserialization_pattern.search(line):
                col_offset = max(0, line.find("ObjectInputStream") if "ObjectInputStream" in line else line.find("readObject"))
                self.findings.append(Finding(
                    rule_id="SEC-JV-004",
                    title="Insecure Deserialization via ObjectInputStream",
                    description="Java ObjectInputStream used for deserialization. Standard Java deserialization is inherently unsafe when handling untrusted streams.",
                    severity="Critical",
                    language="java",
                    line=line_idx,
                    column=col_offset,
                    evidence=stripped,
                    risk_explanation="Adversaries can craft gadget chains (e.g. CommonsCollections, Spring) that execute arbitrary commands upon readObject invocation.",
                    mitigation="Do not deserialize untrusted data with Java native serialization. If required, implement Java ObjectInputFilter or use safe data interchange formats such as JSON or Protocol Buffers.",
                    owasp_references=[
                        "https://owasp.org/www-project-top-ten/2021/A08_Software_and_Data_Integrity_Failures/",
                        "https://cwe.mitre.org/data/definitions/502.html"
                    ],
                    confidence="High",
                    owasp_category="A08:2021 – Software and Data Integrity Failures"
                ))

            # SEC-JV-005: Weak Cryptography
            if weak_crypto_pattern.search(line):
                col_offset = max(0, line.find("getInstance"))
                algo = "MD5/SHA-1/DES"
                if "md5" in line.lower():
                    algo = "MD5"
                elif "sha-1" in line.lower() or "sha1" in line.lower():
                    algo = "SHA-1"
                elif "des" in line.lower():
                    algo = "DES"

                self.findings.append(Finding(
                    rule_id="SEC-JV-005",
                    title=f"Use of Weak Cryptographic Algorithm ({algo})",
                    description=f"Cryptographic algorithm '{algo}' provides inadequate collision resistance and is considered broken for secure operations.",
                    severity="Medium",
                    language="java",
                    line=line_idx,
                    column=col_offset,
                    evidence=stripped,
                    risk_explanation="Weak algorithms allow practical collision attacks, digital signature falsification, or brute-force key discovery.",
                    mitigation="Upgrade to strong algorithms: SHA-256 or SHA-512 for hashing, AES-256 (GCM mode) for symmetric encryption, and Argon2/PBKDF2 for password storage.",
                    owasp_references=[
                        "https://owasp.org/www-project-top-ten/2021/A02_Cryptographic_Failures/",
                        "https://cwe.mitre.org/data/definitions/328.html"
                    ],
                    confidence="High",
                    owasp_category="A02:2021 – Cryptographic Failures"
                ))

        return self.findings
