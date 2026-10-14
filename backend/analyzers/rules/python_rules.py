import ast
import re
from typing import List
from .base_rule import Finding


class PythonSecurityVisitor(ast.NodeVisitor):
    """
    AST Visitor implementing deterministic static security rules for Python.
    Strictly inspects the syntax tree without executing any code.
    """

    def __init__(self, source_lines: List[str]):
        super().__init__()
        self.source_lines = source_lines
        self.findings: List[Finding] = []

    def _get_line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call):
        func_name = ""
        full_call_name = ""

        # Direct name call: eval(...) or exec(...)
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            full_call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                full_call_name = f"{node.func.value.id}.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute):
                # E.g. hashlib.md5 or os.system
                full_call_name = f"{node.func.attr}"

        line_no = getattr(node, "lineno", 1)
        col_offset = getattr(node, "col_offset", 0)
        snippet = self._get_line_snippet(line_no)

        # Rule SEC-PY-001: Unsafe eval / exec
        if func_name in ("eval", "exec"):
            self.findings.append(Finding(
                rule_id="SEC-PY-001",
                title=f"Unsafe Dynamic Code Execution via {func_name}()",
                description=f"Direct invocation of '{func_name}()' parses and executes arbitrary input as Python code, allowing Remote Code Execution (RCE) if supplied with untrusted data.",
                severity="Critical",
                language="python",
                line=line_no,
                column=col_offset,
                evidence=snippet,
                risk_explanation="Attackers can pass malicious payloads that execute arbitrary operating system commands or access unauthorized application memory.",
                mitigation="Avoid eval() and exec(). Use ast.literal_eval() for parsing safe literal data structures, or use dedicated domain-specific parsers.",
                owasp_references=[
                    "https://owasp.org/www-project-top-ten/2021/A03_Injection/",
                    "https://cwe.mitre.org/data/definitions/95.html"
                ],
                confidence="High",
                owasp_category="A03:2021 – Injection"
            ))

        # Rule SEC-PY-002: Dangerous Subprocess Patterns (especially shell=True or os.system)
        if full_call_name in ("os.system", "os.popen"):
            self.findings.append(Finding(
                rule_id="SEC-PY-002",
                title=f"Dangerous Command Execution via {full_call_name}()",
                description=f"Invocation of '{full_call_name}()' executes shell commands directly without parameterization, exposing the host system to OS command injection.",
                severity="Critical",
                language="python",
                line=line_no,
                column=col_offset,
                evidence=snippet,
                risk_explanation="Untrusted input passed to shell execution functions allows adversaries to append or alter commands via shell metacharacters (e.g. ';', '&&', '|').",
                mitigation="Refactor to use 'subprocess.run()' with argument list format and shell=False (default). Never pass concatenated string commands to a shell.",
                owasp_references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/78.html"
                ],
                confidence="High",
                owasp_category="A03:2021 – Injection"
            ))

        if "subprocess" in full_call_name or func_name in ("Popen", "run", "call", "check_call", "check_output"):
            # Check for shell=True keyword argument
            for kw in node.keywords:
                if kw.arg == "shell":
                    is_true = False
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        is_true = True
                    elif hasattr(ast, "NameConstant") and isinstance(kw.value, getattr(ast, "NameConstant")) and kw.value.value is True:
                        is_true = True

                    if is_true:
                        self.findings.append(Finding(
                            rule_id="SEC-PY-002",
                            title="Dangerous Subprocess Execution with shell=True",
                            description="subprocess invoked with 'shell=True'. This spawns an intermediate system shell that interprets metacharacters, leading to OS Command Injection.",
                            severity="Critical",
                            language="python",
                            line=line_no,
                            column=col_offset,
                            evidence=snippet,
                            risk_explanation="If any portion of the command string is derived from untrusted input, arbitrary shell commands can be executed on the server.",
                            mitigation="Set shell=False and pass arguments as an array/list of strings: subprocess.run(['cmd', arg1, arg2], shell=False).",
                            owasp_references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                                "https://cwe.mitre.org/data/definitions/78.html"
                            ],
                            confidence="High",
                            owasp_category="A03:2021 – Injection"
                        ))

        # Rule SEC-PY-003: Potential SQL Injection via string formatting/concatenation in DB execution
        if func_name in ("execute", "executemany", "raw", "raw_query"):
            if node.args:
                first_arg = node.args[0]
                is_dynamic_query = False
                # Check if first argument is f-string (JoinedStr)
                if isinstance(first_arg, ast.JoinedStr):
                    is_dynamic_query = True
                # Check if formatted with % operator: BinOp with Mod
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Mod, ast.Add)):
                    is_dynamic_query = True
                # Check if .format() call on a string: "SELECT ...".format(...)
                elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                    is_dynamic_query = True

                if is_dynamic_query:
                    self.findings.append(Finding(
                        rule_id="SEC-PY-003",
                        title=f"Potential SQL Injection in {func_name}() query",
                        description=f"Query constructed using dynamic string interpolation (f-string, concatenation '+', '%', or '.format()') inside '{func_name}()'.",
                        severity="High",
                        language="python",
                        line=line_no,
                        column=col_offset,
                        evidence=snippet,
                        risk_explanation="Dynamic string interpolation allows untrusted user input to escape SQL syntax boundaries, resulting in unauthorized data exfiltration, modification, or table drops.",
                        mitigation="Use parameterized queries / prepared statements with placeholders (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))).",
                        owasp_references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            "https://owasp.org/www-project-top-ten/2021/A03_Injection/"
                        ],
                        confidence="High",
                        owasp_category="A03:2021 – Injection"
                    ))

        # Rule SEC-PY-005: Unsafe Deserialization
        if full_call_name in ("pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load", "shelve.open", "marshal.loads"):
            self.findings.append(Finding(
                rule_id="SEC-PY-005",
                title=f"Insecure Deserialization via {full_call_name}()",
                description=f"Use of Python '{full_call_name}()' deserializer. The pickle module allows constructor execution during unpickling, which can be weaponized for arbitrary code execution.",
                severity="Critical",
                language="python",
                line=line_no,
                column=col_offset,
                evidence=snippet,
                risk_explanation="Deserializing untrusted pickle streams allows an attacker to instantiate objects that invoke arbitrary callables (e.g. os.system).",
                mitigation="Do not use pickle for untrusted or external input. Use safe, standard data serialization formats such as JSON, Protocol Buffers, or messagepack.",
                owasp_references=[
                    "https://owasp.org/www-project-top-ten/2021/A08_Software_and_Data_Integrity_Failures/",
                    "https://cwe.mitre.org/data/definitions/502.html"
                ],
                confidence="High",
                owasp_category="A08:2021 – Software and Data Integrity Failures"
            ))

        # PyYAML unsafe load: yaml.load without Loader=yaml.SafeLoader
        if full_call_name in ("yaml.load",) or (func_name == "load" and "yaml" in snippet):
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    if isinstance(kw.value, ast.Attribute) and kw.value.attr in ("SafeLoader", "CSafeLoader"):
                        has_safe_loader = True
            if not has_safe_loader:
                self.findings.append(Finding(
                    rule_id="SEC-PY-005",
                    title="Insecure YAML Deserialization via yaml.load()",
                    description="yaml.load() invoked without SafeLoader allows deserialization of arbitrary Python objects, leading to Remote Code Execution.",
                    severity="Critical",
                    language="python",
                    line=line_no,
                    column=col_offset,
                    evidence=snippet,
                    risk_explanation="YAML deserialization with default Loader can execute Python constructors specified in !!python/object tags.",
                    mitigation="Use yaml.safe_load(data) or specify Loader=yaml.SafeLoader.",
                    owasp_references=[
                        "https://owasp.org/www-project-top-ten/2021/A08_Software_and_Data_Integrity_Failures/",
                        "https://cwe.mitre.org/data/definitions/502.html"
                    ],
                    confidence="High",
                    owasp_category="A08:2021 – Software and Data Integrity Failures"
                ))

        # Rule SEC-PY-006: Weak Cryptographic Algorithms (MD5 / SHA-1)
        if full_call_name in ("hashlib.md5", "hashlib.sha1") or (func_name in ("md5", "sha1") and "hashlib" in snippet):
            algo_name = "MD5" if "md5" in full_call_name.lower() or "md5" in func_name.lower() else "SHA-1"
            self.findings.append(Finding(
                rule_id="SEC-PY-006",
                title=f"Use of Weak Cryptographic Hash ({algo_name})",
                description=f"Cryptographic hash algorithm '{algo_name}' is collision-vulnerable and cryptographically broken for security-sensitive applications.",
                severity="Medium",
                language="python",
                line=line_no,
                column=col_offset,
                evidence=snippet,
                risk_explanation="MD5 and SHA-1 suffer from proven practical collision attacks, permitting forgery of signatures, tokens, and certificates.",
                mitigation="Migrate to SHA-256 (hashlib.sha256), SHA-384, or SHA-512. For passwords, use dedicated password hashing functions such as Argon2id, bcrypt, or PBKDF2.",
                owasp_references=[
                    "https://owasp.org/www-project-top-ten/2021/A02_Cryptographic_Failures/",
                    "https://cwe.mitre.org/data/definitions/328.html"
                ],
                confidence="High",
                owasp_category="A02:2021 – Cryptographic Failures"
            ))

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Rule SEC-PY-004: Hardcoded credentials and secrets
        line_no = getattr(node, "lineno", 1)
        col_offset = getattr(node, "col_offset", 0)
        snippet = self._get_line_snippet(line_no)

        secret_name_regex = re.compile(
            r'^(?:.*_)?(password|passwd|secret|api_key|apikey|auth_token|jwt_secret|private_key|access_token|db_pass)(?:_.*)?$',
            re.IGNORECASE
        )

        for target in node.targets:
            target_name = ""
            if isinstance(target, ast.Name):
                target_name = target.id
            elif isinstance(target, ast.Attribute):
                target_name = target.attr

            if target_name and secret_name_regex.match(target_name):
                # Check if value is a non-empty string literal
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val_str = node.value.value.strip()
                    # Filter out placeholders like "", "TODO", "CHANGEME", "env", "None"
                    if len(val_str) >= 4 and not val_str.startswith("$") and val_str.lower() not in ("none", "null", "false", "true", "dummy"):
                        # Mask the evidence for privacy
                        masked_snippet = re.sub(r'([\'"]).*?([\'"])', r'\1********\2', snippet)
                        self.findings.append(Finding(
                            rule_id="SEC-PY-004",
                            title=f"Hardcoded Credential or Secret in '{target_name}'",
                            description=f"Variable '{target_name}' is assigned an inline string literal containing sensitive credential or secret data.",
                            severity="High",
                            language="python",
                            line=line_no,
                            column=col_offset,
                            evidence=masked_snippet,
                            risk_explanation="Hardcoded secrets in source code are frequently leaked via version control, decompilation, logs, or third-party audits.",
                            mitigation="Store credentials in environment variables (e.g. os.getenv) or use a dedicated secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager).",
                            owasp_references=[
                                "https://owasp.org/www-project-top-ten/2021/A07_Identification_and_Authentication_Failures/",
                                "https://cwe.mitre.org/data/definitions/798.html"
                            ],
                            confidence="High",
                            owasp_category="A07:2021 – Identification and Authentication Failures"
                        ))

        self.generic_visit(node)
