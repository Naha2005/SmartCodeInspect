import ast
import re
from typing import List, Dict, Any, Optional, Set, Tuple

try:
    from analyzers.rules.base_rule import Finding
except ImportError:
    try:
        from backend.analyzers.rules.base_rule import Finding
    except ImportError:
        from ..analyzers.rules.base_rule import Finding


AGENT_NAME = "Code Analysis Agent"


class PythonCodeAnalysisVisitor(ast.NodeVisitor):
    """
    AST Visitor implementing deterministic Code Analysis rules for Python:
    Detects code smells, complexity issues, design anti-patterns, and poor coding practices.
    """

    def __init__(self, source_lines: List[str], with_context_calls: Optional[Set[ast.Call]] = None):
        super().__init__()
        self.source_lines = source_lines
        self.findings: List[Finding] = []
        self._current_nesting = 0
        self._current_function = None
        self._with_context_calls = with_context_calls or set()

    def _get_line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _calculate_cyclomatic_complexity(self, node: ast.AST) -> int:
        """
        Calculate Cyclomatic Complexity (McCabe metric):
        Base complexity = 1 + number of branching decision points.
        """
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.ExceptHandler, ast.Assert)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                # Each 'and' / 'or' adds a decision path
                complexity += len(child.values) - 1
            elif hasattr(ast, "Match") and isinstance(child, getattr(ast, "Match")):
                complexity += len(child.cases)
        return complexity

    def _count_boolean_operators(self, node: ast.BoolOp) -> int:
        """Count total boolean operator occurrences in a boolean expression."""
        count = len(node.values) - 1
        for val in node.values:
            if isinstance(val, ast.BoolOp):
                count += self._count_boolean_operators(val)
        return count

    def visit_ImportFrom(self, node: ast.ImportFrom):
        # Rule SMELL-PY-005: Wildcard Import Smell
        line_no = getattr(node, "lineno", 1)
        for alias in node.names:
            if alias.name == "*":
                mod_name = node.module or ""
                self.findings.append(Finding(
                    rule_id="SMELL-PY-005",
                    title="Wildcard Import Namespace Pollution",
                    description=f"Wildcard import 'from {mod_name} import *' pollutes the local namespace, obscures variable origins, and risks accidental symbol shadowing.",
                    severity="Low",
                    severity_score=2.5,
                    language="python",
                    line=line_no,
                    column=getattr(node, "col_offset", 0),
                    evidence=self._get_line_snippet(line_no),
                    risk_explanation="Importing everything with '*' creates maintenance hurdles, slows static analysis, and can cause unexpected variable collisions.",
                    mitigation="Explicitly import only the specific required classes, functions, or constants, or import the module directly.",
                    owasp_references=["https://peps.python.org/pep-0008/#imports"],
                    confidence="High",
                    category="Code Smell",
                    agent=AGENT_NAME
                ))
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        line_no = getattr(node, "lineno", 1)
        end_line = getattr(node, "end_lineno", line_no)
        class_lines = end_line - line_no + 1

        # Count methods
        methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        method_count = len(methods)

        # Rule SMELL-PY-003: Large / Bloated Class Smell
        if class_lines > 150 or method_count > 12:
            self.findings.append(Finding(
                rule_id="SMELL-PY-003",
                title=f"Large / Bloated Class '{node.name}'",
                description=f"Class '{node.name}' spans {class_lines} lines with {method_count} methods, exceeding recommended modularity boundaries.",
                severity="Medium",
                severity_score=4.8,
                language="python",
                line=line_no,
                column=getattr(node, "col_offset", 0),
                evidence=self._get_line_snippet(line_no),
                risk_explanation="Large classes often violate the Single Responsibility Principle, making maintenance, unit testing, and refactoring error-prone.",
                mitigation="Decompose this class into smaller, cohesive classes using composition or domain-driven interfaces.",
                owasp_references=["https://refactoring.guru/smells/large-class"],
                confidence="High",
                category="Code Smell",
                agent=AGENT_NAME
            ))

        # Rule DESIGN-PY-002: God Class Anti-Pattern (>250 lines and >18 methods)
        if class_lines > 250 and method_count > 18:
            self.findings.append(Finding(
                rule_id="DESIGN-PY-002",
                title=f"God Class Anti-Pattern '{node.name}'",
                description=f"Class '{node.name}' aggregates excessive system responsibilities ({class_lines} lines, {method_count} methods), acting as a centralized God Object.",
                severity="High",
                severity_score=7.2,
                language="python",
                line=line_no,
                column=getattr(node, "col_offset", 0),
                evidence=self._get_line_snippet(line_no),
                risk_explanation="God objects create tight coupling across subsystems, hinder code reusability, and create critical failure points.",
                mitigation="Refactor responsibilities into cohesive collaborator objects adhering to Single Responsibility Principle (SRP).",
                owasp_references=["https://en.wikipedia.org/wiki/God_object"],
                confidence="High",
                category="Design Anti-Pattern",
                agent=AGENT_NAME
            ))

        # Rule PRACTICE-PY-005: PEP 8 Naming Convention for Classes (PascalCase)
        # Unique rule ID distinct from function naming
        if not re.match(r"^[A-Z][a-zA-Z0-9]+$", node.name):
            self.findings.append(Finding(
                rule_id="PRACTICE-PY-005",
                title=f"PEP 8 Class Naming Violation '{node.name}'",
                description=f"Class name '{node.name}' does not follow Python PEP 8 CapWords (PascalCase) convention.",
                severity="Informational",
                severity_score=1.5,
                language="python",
                line=line_no,
                column=getattr(node, "col_offset", 0),
                evidence=self._get_line_snippet(line_no),
                risk_explanation="Inconsistent naming styles degrade codebase readability and violate standard Python conventions.",
                mitigation="Rename the class using PascalCase (e.g. 'CustomerAccountManager').",
                owasp_references=["https://peps.python.org/pep-0008/#class-names"],
                confidence="High",
                category="Poor Coding Practice",
                agent=AGENT_NAME
            ))

        # Rule PRACTICE-PY-006: Missing Class Docstring on substantial classes (>15 lines)
        # Unique rule ID distinct from function docstrings
        if class_lines > 15 and not ast.get_docstring(node):
            self.findings.append(Finding(
                rule_id="PRACTICE-PY-006",
                title=f"Missing Docstring on Class '{node.name}'",
                description=f"Class '{node.name}' lacks a descriptive docstring explaining its architectural purpose and contract.",
                severity="Informational",
                severity_score=1.0,
                language="python",
                line=line_no,
                column=getattr(node, "col_offset", 0),
                evidence=self._get_line_snippet(line_no),
                risk_explanation="Undocumented classes increase onboarding overhead and reduce maintainability.",
                mitigation="Add a concise triple-quoted docstring summarizing the class responsibilities.",
                owasp_references=["https://peps.python.org/pep-0257/"],
                confidence="High",
                category="Poor Coding Practice",
                agent=AGENT_NAME
            ))

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._analyze_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._analyze_function(node)

    def _analyze_function(self, node):
        line_no = getattr(node, "lineno", 1)
        end_line = getattr(node, "end_lineno", line_no)
        func_lines = end_line - line_no + 1

        prev_func = self._current_function
        self._current_function = node.name

        # Rule SMELL-PY-001: Long Function Smell (>30 lines)
        if func_lines > 30:
            sev = "Medium" if func_lines > 60 else "Low"
            score = 5.2 if func_lines > 60 else 3.5
            self.findings.append(Finding(
                rule_id="SMELL-PY-001",
                title=f"Long Function/Method Smell in '{node.name}()'",
                description=f"Function '{node.name}' spans {func_lines} lines of code, exceeding the 30-line clean code guideline.",
                severity=sev,
                severity_score=score,
                language="python",
                line=line_no,
                column=getattr(node, "col_offset", 0),
                evidence=self._get_line_snippet(line_no),
                risk_explanation="Long functions typically perform multiple disparate tasks, making unit testing difficult and hiding logic bugs.",
                mitigation="Extract cohesive sub-tasks into well-named private helper functions.",
                owasp_references=["https://refactoring.guru/smells/long-method"],
                confidence="High",
                category="Code Smell",
                agent=AGENT_NAME
            ))

        # Rule SMELL-PY-002: Long Parameter List (>5 parameters across all parameter types)
        all_args = []
        if hasattr(node.args, "posonlyargs"):
            all_args.extend(node.args.posonlyargs)
        all_args.extend(node.args.args)
        all_args.extend(node.args.kwonlyargs)

        param_names = [a.arg for a in all_args if a.arg not in ("self", "cls")]
        if node.args.vararg:
            param_names.append(f"*{node.args.vararg.arg}")
        if node.args.kwarg:
            param_names.append(f"**{node.args.kwarg.arg}")

        param_count = len(param_names)
        if param_count > 5:
            self.findings.append(Finding(
                rule_id="SMELL-PY-002",
                title=f"Long Parameter List in '{node.name}()' ({param_count} parameters)",
                description=f"Function '{node.name}' defines {param_count} parameters, exceeding recommended threshold of 5.",
                severity="Low",
                severity_score=3.0,
                language="python",
                line=line_no,
                column=getattr(node, "col_offset", 0),
                evidence=self._get_line_snippet(line_no),
                risk_explanation="Functions with excessive parameters are difficult to invoke correctly and increase coupling.",
                mitigation="Encapsulate related parameters into a dedicated dataclass, Pydantic model, or parameter object.",
                owasp_references=["https://refactoring.guru/smells/long-parameter-list"],
                confidence="High",
                category="Code Smell",
                agent=AGENT_NAME
            ))

        # Rule DESIGN-PY-001: Mutable Default Argument Anti-Pattern
        for default in node.args.defaults + node.args.kw_defaults:
            if default is not None and isinstance(default, (ast.List, ast.Dict, ast.Set)):
                def_line = getattr(default, "lineno", line_no)
                self.findings.append(Finding(
                    rule_id="DESIGN-PY-001",
                    title=f"Mutable Default Argument in '{node.name}()'",
                    description=f"Function '{node.name}' defines a mutable default argument ({type(default).__name__}). In Python, default arguments are evaluated once at definition time and shared across all invocations.",
                    severity="High",
                    severity_score=7.5,
                    language="python",
                    line=def_line,
                    column=getattr(default, "col_offset", 0),
                    evidence=self._get_line_snippet(def_line),
                    risk_explanation="Modifying a mutable default parameter mutates state across subsequent calls, introducing subtle, non-deterministic bugs.",
                    mitigation="Set default value to 'None' and initialize a new mutable object inside the function: 'if arg is None: arg = []'.",
                    owasp_references=["https://docs.python-guide.org/writing/gotchas/#mutable-default-arguments"],
                    confidence="High",
                    category="Design Anti-Pattern",
                    agent=AGENT_NAME
                ))

        # Rule COMPLEX-PY-001: High Cyclomatic Complexity
        cc = self._calculate_cyclomatic_complexity(node)
        if cc > 8:
            sev = "High" if cc > 15 else "Medium"
            score = 8.0 if cc > 15 else 6.0
            self.findings.append(Finding(
                rule_id="COMPLEX-PY-001",
                title=f"High Cyclomatic Complexity in '{node.name}()' (CC = {cc})",
                description=f"Function '{node.name}' exhibits cyclomatic complexity of {cc} (threshold is 8). It contains numerous branching paths.",
                severity=sev,
                severity_score=score,
                language="python",
                line=line_no,
                column=getattr(node, "col_offset", 0),
                evidence=self._get_line_snippet(line_no),
                risk_explanation="High cyclomatic complexity significantly increases test burden and defect probability.",
                mitigation="Break down complex conditional trees using guard clauses, lookup dictionaries, or strategy patterns.",
                owasp_references=["https://en.wikipedia.org/wiki/Cyclomatic_complexity"],
                confidence="High",
                category="Complexity",
                agent=AGENT_NAME
            ))

        # Rule PRACTICE-PY-003: PEP 8 Naming Convention for Functions (snake_case)
        if not node.name.startswith("__") and not re.match(r"^[a-z_][a-z0-9_]*$", node.name):
            self.findings.append(Finding(
                rule_id="PRACTICE-PY-003",
                title=f"PEP 8 Function Naming Violation '{node.name}'",
                description=f"Function name '{node.name}' violates Python PEP 8 snake_case naming style.",
                severity="Informational",
                severity_score=1.5,
                language="python",
                line=line_no,
                column=getattr(node, "col_offset", 0),
                evidence=self._get_line_snippet(line_no),
                risk_explanation="Non-standard naming violates conventions and reduces clarity for Python developers.",
                mitigation="Rename the function using lowercase words separated by underscores (e.g. 'calculate_tax_rate').",
                owasp_references=["https://peps.python.org/pep-0008/#function-and-variable-names"],
                confidence="High",
                category="Poor Coding Practice",
                agent=AGENT_NAME
            ))

        # Rule PRACTICE-PY-004: Missing Function Docstring on substantial functions (>15 lines)
        if func_lines > 15 and not node.name.startswith("_") and not ast.get_docstring(node):
            self.findings.append(Finding(
                rule_id="PRACTICE-PY-004",
                title=f"Missing Docstring on Public Function '{node.name}()'",
                description=f"Public function '{node.name}' does not include a docstring describing its arguments, return values, and behavior.",
                severity="Informational",
                severity_score=1.0,
                language="python",
                line=line_no,
                column=getattr(node, "col_offset", 0),
                evidence=self._get_line_snippet(line_no),
                risk_explanation="Undocumented public functions complicate API consumption and code reviews.",
                mitigation="Provide a concise docstring specifying parameters and return types.",
                owasp_references=["https://peps.python.org/pep-0257/"],
                confidence="High",
                category="Poor Coding Practice",
                agent=AGENT_NAME
            ))

        # Track nesting
        self.generic_visit(node)
        self._current_function = prev_func

    def visit_If(self, node: ast.If):
        self._check_nesting(node)
        self.generic_visit(node)
        self._pop_nesting()

    def visit_For(self, node: ast.For):
        self._check_nesting(node)
        self.generic_visit(node)
        self._pop_nesting()

    def visit_AsyncFor(self, node: ast.AsyncFor):
        self._check_nesting(node)
        self.generic_visit(node)
        self._pop_nesting()

    def visit_While(self, node: ast.While):
        self._check_nesting(node)
        self.generic_visit(node)
        self._pop_nesting()

    def visit_Try(self, node: ast.Try):
        self._check_nesting(node)
        self.generic_visit(node)
        self._pop_nesting()

    def _check_nesting(self, node):
        self._current_nesting += 1
        if self._current_nesting >= 4:
            line_no = getattr(node, "lineno", 1)
            # Avoid duplicate reporting for immediate children on same line
            if not any(f.rule_id == "COMPLEX-PY-002" and f.line == line_no for f in self.findings):
                self.findings.append(Finding(
                    rule_id="COMPLEX-PY-002",
                    title="Deep Control Flow Nesting (Arrow Anti-Pattern)",
                    description=f"Control flow nesting reached depth {self._current_nesting}, creating deeply indented blocks.",
                    severity="Medium",
                    severity_score=5.5,
                    language="python",
                    line=line_no,
                    column=getattr(node, "col_offset", 0),
                    evidence=self._get_line_snippet(line_no),
                    risk_explanation="Deeply nested structures obscure execution flow, increase cognitive load, and frequently conceal edge-case bugs.",
                    mitigation="Refactor using early return guard clauses, polymorphism, or extract nested blocks into helper functions.",
                    owasp_references=["https://en.wikipedia.org/wiki/Spaghetti_code"],
                    confidence="High",
                    category="Complexity",
                    agent=AGENT_NAME
                ))

    def _pop_nesting(self):
        if self._current_nesting > 0:
            self._current_nesting -= 1

    def visit_BoolOp(self, node: ast.BoolOp):
        op_count = self._count_boolean_operators(node)
        if op_count >= 3:
            line_no = getattr(node, "lineno", 1)
            self.findings.append(Finding(
                rule_id="COMPLEX-PY-003",
                title=f"Complex Boolean Expression ({op_count} chained logical operators)",
                description=f"Expression combines {op_count} logical operators ('and' / 'or'), forming a difficult-to-parse boolean expression.",
                severity="Low",
                severity_score=3.0,
                language="python",
                line=line_no,
                column=getattr(node, "col_offset", 0),
                evidence=self._get_line_snippet(line_no),
                risk_explanation="Complex compound boolean expressions are prone to operator precedence misunderstandings and logic inversions.",
                mitigation="Decompose complex condition into descriptive boolean variables (e.g. 'is_eligible_user = ...').",
                owasp_references=["https://refactoring.guru/decompose-conditional"],
                confidence="High",
                category="Complexity",
                agent=AGENT_NAME
            ))
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        line_no = getattr(node, "lineno", 1)

        # Rule SMELL-PY-004: Empty Exception Handler / Silenced Errors
        is_empty = False
        if len(node.body) == 1:
            first_stmt = node.body[0]
            if isinstance(first_stmt, ast.Pass):
                is_empty = True
            elif isinstance(first_stmt, ast.Expr) and isinstance(first_stmt.value, ast.Constant):
                # Ellipsis (...) or literal
                is_empty = True

        if is_empty:
            self.findings.append(Finding(
                rule_id="SMELL-PY-004",
                title="Empty Exception Handler (Silenced Error)",
                description="Exception block catches an error and silently suppresses it without logging, re-raising, or recovery logic.",
                severity="Medium",
                severity_score=5.5,
                language="python",
                line=line_no,
                column=getattr(node, "col_offset", 0),
                evidence=self._get_line_snippet(line_no),
                risk_explanation="Silently swallowing exceptions masks system errors, corrupts application state, and complicates troubleshooting.",
                mitigation="Log the caught exception using a structured logger or handle the specific recovery condition explicitly.",
                owasp_references=["https://cwe.mitre.org/data/definitions/390.html"],
                confidence="High",
                category="Code Smell",
                agent=AGENT_NAME
            ))

        # Rule DESIGN-PY-003: Catch-All Generic Exception
        is_generic = False
        if node.type is None:  # bare except:
            is_generic = True
        elif isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
            is_generic = True

        if is_generic and not is_empty:
            self.findings.append(Finding(
                rule_id="DESIGN-PY-003",
                title="Catch-All Generic Exception Handling",
                description="Catching broad 'Exception' or 'BaseException' intercepts unexpected runtime errors (e.g. MemoryError, KeyboardInterrupt, KeyError) instead of targeted error states.",
                severity="Medium",
                severity_score=4.5,
                language="python",
                line=line_no,
                column=getattr(node, "col_offset", 0),
                evidence=self._get_line_snippet(line_no),
                risk_explanation="Catching overly broad exceptions masks bugs and prevents graceful degradation.",
                mitigation="Catch specific exception types (e.g. 'ValueError', 'FileNotFoundError') rather than generic Exception.",
                owasp_references=["https://docs.python.org/3/tutorial/errors.html#handling-exceptions"],
                confidence="High",
                category="Design Anti-Pattern",
                agent=AGENT_NAME
            ))

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        line_no = getattr(node, "lineno", 1)
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

        # Rule PRACTICE-PY-001: Print in Production Code
        if func_name == "print":
            self.findings.append(Finding(
                rule_id="PRACTICE-PY-001",
                title="Print Statement Left in Production Code",
                description="Invocation of built-in 'print()' statement detected. Production services should utilize structured logging.",
                severity="Low",
                severity_score=2.0,
                language="python",
                line=line_no,
                column=getattr(node, "col_offset", 0),
                evidence=self._get_line_snippet(line_no),
                risk_explanation="Print statements cannot be filtered by log levels, lack contextual timestamps, and can leak sensitive data into unmanaged stdout.",
                mitigation="Replace 'print()' with standard library 'logging.getLogger(__name__)' at appropriate severity levels.",
                owasp_references=["https://docs.python.org/3/howto/logging.html"],
                confidence="High",
                category="Poor Coding Practice",
                agent=AGENT_NAME
            ))

        # Rule PRACTICE-PY-002: Resource Leak (open without with)
        # AST-verified check: only flags open() when not part of a With context expression
        if func_name == "open":
            if node not in self._with_context_calls:
                self.findings.append(Finding(
                    rule_id="PRACTICE-PY-002",
                    title="Potential Resource Leak via Unmanaged File Open",
                    description="'open()' called outside of a 'with' context manager. If an exception occurs before close(), the file descriptor may leak.",
                    severity="Medium",
                    severity_score=5.5,
                    language="python",
                    line=line_no,
                    column=getattr(node, "col_offset", 0),
                    evidence=self._get_line_snippet(line_no),
                    risk_explanation="Unclosed file descriptors cause resource exhaustion, especially under high concurrency.",
                    mitigation="Use 'with open(...) as f:' context manager to ensure automatic descriptor cleanup.",
                    owasp_references=["https://cwe.mitre.org/data/definitions/775.html"],
                    confidence="High",
                    category="Poor Coding Practice",
                    agent=AGENT_NAME
                ))

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        # Rule DESIGN-PY-004: Magic Numbers
        if isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            val = node.value
            # Ignore standard neutral constants (0, 1, 2, -1, 100, etc.)
            if val not in (0, 1, 2, -1, 100, 0.0, 1.0) and abs(val) > 2:
                line_no = getattr(node, "lineno", 1)
                snippet = self._get_line_snippet(line_no)
                # Only flag if used in arithmetic, comparison, or call, not standalone assignment to ALL_CAPS
                if "=" in snippet and not any(k in snippet for k in ("==", "<", ">", "<=", ">=")):
                    lhs = snippet.split("=")[0].strip()
                    if lhs.isupper():  # Already a declared constant
                        self.generic_visit(node)
                        return
                # Check if inside an if/while or calculation
                if any(k in snippet for k in ("if ", "elif ", "while ", "return ", "*", "/", "+", "-")):
                    # Avoid duplicate magic number reports on same line
                    if not any(f.rule_id == "DESIGN-PY-004" and f.line == line_no for f in self.findings):
                        self.findings.append(Finding(
                            rule_id="DESIGN-PY-004",
                            title=f"Magic Number Literal '{val}'",
                            description=f"Hardcoded numeric constant '{val}' used directly in logic without a descriptive named constant.",
                            severity="Low",
                            severity_score=2.0,
                            language="python",
                            line=line_no,
                            column=getattr(node, "col_offset", 0),
                            evidence=snippet,
                            risk_explanation="Magic numbers obscure business rationale and create duplicate maintenance points when values change.",
                            mitigation=f"Declare a descriptive constant at module level (e.g. 'MAX_RETRY_COUNT = {val}').",
                            owasp_references=["https://en.wikipedia.org/wiki/Magic_number_(programming)"],
                            confidence="Medium",
                            category="Design Anti-Pattern",
                            agent=AGENT_NAME
                        ))
        self.generic_visit(node)


class JavaCodeAnalysisScanner:
    """
    Deterministic static code analysis scanner for Java source code.
    Detects code smells, complexity issues, design anti-patterns, and poor coding practices.
    Uses accurate string/comment masking and brace matching for robust multiline analysis.
    """

    CONTROL_RE = re.compile(r"\b(?:if|for|while|do|switch|try|catch)\b")

    METHOD_RE = re.compile(
        r"(?:(?:public|protected|private|static|final|synchronized|abstract|default)\s+)+"
        r"(?:<[^>]+>\s+)?[\w<>\[\],\s]+\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*\{"
    )

    def __init__(self, source_code: str):
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.masked = self._mask_code(source_code)
        self.masked_lines = self.masked.splitlines()
        self.findings: List[Finding] = []

    @staticmethod
    def _mask_code(source: str) -> str:
        """
        Mask comments, string literals, and character literals with spaces,
        preserving exact character offsets, length, and newline positions.
        """
        chars = list(source)
        n = len(chars)
        i = 0
        while i < n:
            # Single-line comment: // ...
            if i + 1 < n and chars[i] == '/' and chars[i + 1] == '/':
                chars[i] = ' '
                chars[i + 1] = ' '
                i += 2
                while i < n and chars[i] != '\n':
                    chars[i] = ' '
                    i += 1
            # Multi-line comment: /* ... */
            elif i + 1 < n and chars[i] == '/' and chars[i + 1] == '*':
                chars[i] = ' '
                chars[i + 1] = ' '
                i += 2
                while i < n:
                    if i + 1 < n and chars[i] == '*' and chars[i + 1] == '/':
                        chars[i] = ' '
                        chars[i + 1] = ' '
                        i += 2
                        break
                    if chars[i] != '\n':
                        chars[i] = ' '
                    i += 1
            # String literal: " ... "
            elif chars[i] == '"':
                chars[i] = ' '
                i += 1
                while i < n and chars[i] != '"':
                    if chars[i] == '\\' and i + 1 < n:
                        chars[i] = ' '
                        if chars[i + 1] != '\n':
                            chars[i + 1] = ' '
                        i += 2
                    else:
                        if chars[i] != '\n':
                            chars[i] = ' '
                        i += 1
                if i < n and chars[i] == '"':
                    chars[i] = ' '
                    i += 1
            # Character literal: ' ... '
            elif chars[i] == "'":
                chars[i] = ' '
                i += 1
                while i < n and chars[i] != "'":
                    if chars[i] == '\\' and i + 1 < n:
                        chars[i] = ' '
                        if chars[i + 1] != '\n':
                            chars[i + 1] = ' '
                        i += 2
                    else:
                        if chars[i] != '\n':
                            chars[i] = ' '
                        i += 1
                if i < n and chars[i] == "'":
                    chars[i] = ' '
                    i += 1
            else:
                i += 1
        return "".join(chars)

    def _brace_pairs(self) -> Dict[int, int]:
        """Map opening brace character offset to corresponding closing brace offset."""
        pairs = {}
        stack = []
        for offset, ch in enumerate(self.masked):
            if ch == '{':
                stack.append(offset)
            elif ch == '}':
                if stack:
                    opening = stack.pop()
                    pairs[opening] = offset
        return pairs

    def _line_for_offset(self, text: str, offset: int) -> int:
        """Calculate 1-indexed line number for a character offset in text."""
        return text.count("\n", 0, offset) + 1

    def _snippet(self, line: int) -> str:
        if 1 <= line <= len(self.source_lines):
            return self.source_lines[line - 1].strip()
        return ""

    @staticmethod
    def _count_parameters(param_str: str) -> int:
        """Accurately count Java parameters, respecting nested generic type arguments."""
        clean = param_str.strip()
        if not clean:
            return 0
        parts = []
        depth = 0
        current = []
        for ch in clean:
            if ch == '<':
                depth += 1
            elif ch == '>':
                depth = max(0, depth - 1)
            elif ch == ',' and depth == 0:
                part = "".join(current).strip()
                if part:
                    parts.append(part)
                current = []
                continue
            current.append(ch)
        if current:
            part = "".join(current).strip()
            if part:
                parts.append(part)
        return len(parts)

    def _add(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: str,
        severity_score: float,
        language: str,
        line: int,
        column: int,
        evidence: str,
        risk_explanation: str,
        mitigation: str,
        references: Optional[List[str]] = None,
        owasp_references: Optional[List[str]] = None,
        confidence: str = "Medium",
        category: str = "Code Smell"
    ):
        refs = owasp_references or references or []
        self.findings.append(Finding(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            severity_score=severity_score,
            language=language,
            line=line,
            column=column,
            evidence=evidence,
            risk_explanation=risk_explanation,
            mitigation=mitigation,
            owasp_references=refs,
            confidence=confidence,
            category=category,
            agent=AGENT_NAME
        ))

    def scan(self) -> List[Finding]:
        self.findings.clear()

        # Regular expressions for Java patterns
        wildcard_import_re = re.compile(r'^\s*import\s+[\w\.]+\.\*\s*;')
        system_out_re = re.compile(r'(\bSystem\.(?:out|err)\.println\s*\(|\.printStackTrace\s*\(\s*\))')
        unclosed_stream_re = re.compile(
            r'\b(?:FileInputStream|FileOutputStream|FileReader|FileWriter|BufferedReader|BufferedWriter)\s+\w+\s*=\s*new\s+'
        )

        pairs = self._brace_pairs()

        # 1. Line-by-line checks for imports, console printing, unclosed streams, and complex boolean expressions
        for line_idx, line in enumerate(self.source_lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            # Check imports
            if wildcard_import_re.match(line):
                self._add(
                    rule_id="SMELL-JV-005",
                    title="Java Wildcard Package Import",
                    description=f"Wildcard import '{stripped}' imports entire package namespace, increasing collision risk and obscuring class origins.",
                    severity="Low",
                    severity_score=2.0,
                    language="java",
                    line=line_idx,
                    column=0,
                    evidence=stripped,
                    risk_explanation="Package wildcard imports cause subtle compiler class shadowing and make dependency tracking harder.",
                    mitigation="Import specific fully-qualified class names individually.",
                    references=["https://google.github.io/styleguide/javaguide.html#s3.3.1-wildcard-imports"],
                    confidence="High",
                    category="Code Smell"
                )

            # Check console print / stack trace
            if system_out_re.search(line):
                self._add(
                    rule_id="PRACTICE-JV-001",
                    title="Console Print / printStackTrace in Production Code",
                    description="Invocation of 'System.out/err.println()' or 'printStackTrace()' detected instead of enterprise logging framework.",
                    severity="Low",
                    severity_score=2.5,
                    language="java",
                    line=line_idx,
                    column=max(0, line.find("System.")),
                    evidence=stripped,
                    risk_explanation="Console printing cannot be filtered, lacks thread/trace IDs, and printStackTrace can expose internal stack traces to users.",
                    mitigation="Use a logging facade such as SLF4J (e.g. 'logger.info(...)', 'logger.error(...)').",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"],
                    confidence="High",
                    category="Poor Coding Practice"
                )

            # Check unclosed stream without try-with-resources
            if unclosed_stream_re.search(line) and "try" not in line:
                self._add(
                    rule_id="PRACTICE-JV-002",
                    title="Unmanaged I/O Stream without Try-With-Resources",
                    description="I/O Stream instantiated outside of a 'try (...) {' try-with-resources statement. Risks file descriptor leaks.",
                    severity="Medium",
                    severity_score=5.8,
                    language="java",
                    line=line_idx,
                    column=0,
                    evidence=stripped,
                    risk_explanation="Unclosed I/O streams leak operating system file handles, eventually exhausting system resources.",
                    mitigation="Wrap the stream initialization in a 'try (...) {' block to ensure automatic closure.",
                    references=["https://cwe.mitre.org/data/definitions/775.html"],
                    confidence="High",
                    category="Poor Coding Practice"
                )

            # Check complex boolean expressions in masked code
            if line_idx - 1 < len(self.masked_lines):
                masked_line = self.masked_lines[line_idx - 1]
                operators = re.findall(r'&&|\|\|', masked_line)
                if len(operators) >= 3:
                    self._add(
                        rule_id="COMPLEX-JV-003",
                        title="Complex Boolean Expression",
                        description=f"Statement contains {len(operators)} boolean operators; consider whether the condition is difficult to read.",
                        severity="Low",
                        severity_score=3.0,
                        language="java",
                        line=line_idx,
                        column=0,
                        evidence=stripped,
                        risk_explanation="Long boolean expressions are harder to verify and maintain.",
                        mitigation="Extract meaningful subconditions into named boolean variables or methods.",
                        references=["https://refactoring.guru/decompose-conditional"],
                        confidence="Medium",
                        category="Complexity"
                    )

        # 2. Robust empty catch and catch-all analysis using masked brace matching
        for catch_match in re.finditer(r'\bcatch\s*\(([^)]*)\)\s*\{', self.masked):
            opening = catch_match.end() - 1
            if opening in pairs:
                closing = pairs[opening]
                inside_body = self.masked[opening + 1:closing].strip()
                line = self._line_for_offset(self.masked, catch_match.start())
                param_decl = catch_match.group(1).strip()

                if not inside_body:
                    self._add(
                        rule_id="SMELL-JV-004",
                        title="Empty Catch Block (Silenced Java Exception)",
                        description="Empty catch block catches an exception but contains no handling, logging, or recovery logic.",
                        severity="Medium",
                        severity_score=5.5,
                        language="java",
                        line=line,
                        column=0,
                        evidence=self._snippet(line),
                        risk_explanation="Empty catch blocks suppress critical failures, leading to corrupt internal state and mysterious downstream errors.",
                        mitigation="Log the exception with SLF4J or recover gracefully.",
                        references=["https://cwe.mitre.org/data/definitions/390.html"],
                        confidence="High",
                        category="Code Smell"
                    )
                elif re.search(r'\b(?:Exception|Throwable)\s+\w+', param_decl):
                    self._add(
                        rule_id="DESIGN-JV-001",
                        title="Catch-All Generic Exception Handling (Exception / Throwable)",
                        description="Catching broad 'Exception' or 'Throwable' intercepts unchecked runtime errors and fatal JVM errors.",
                        severity="Medium",
                        severity_score=4.5,
                        language="java",
                        line=line,
                        column=0,
                        evidence=self._snippet(line),
                        risk_explanation="Catching generic Exception masks unintended programming defects.",
                        mitigation="Catch specific checked exceptions directly.",
                        references=["https://google.github.io/styleguide/javaguide.html#s5.2.3-caught-exceptions"],
                        confidence="High",
                        category="Design Anti-Pattern"
                    )

        # 3. Control-flow nesting depth (tracking only control constructs, excluding class & method braces)
        control_openings = set()
        for match in self.CONTROL_RE.finditer(self.masked):
            brace = self.masked.find("{", match.end())
            semicolon = self.masked.find(";", match.end())
            if brace != -1 and (semicolon == -1 or brace < semicolon) and brace in pairs:
                control_openings.add(brace)

        depth = 0
        events = []
        for opening, closing in pairs.items():
            if opening in control_openings:
                events.append((opening, 1))
                events.append((closing, -1))
        events.sort()

        reported_nesting_lines = set()
        for offset, delta in events:
            depth += delta
            if delta == 1 and depth >= 4:
                line = self._line_for_offset(self.masked, offset)
                if line not in reported_nesting_lines:
                    reported_nesting_lines.add(line)
                    self._add(
                        rule_id="COMPLEX-JV-002",
                        title="Deep Java Control-Flow Nesting",
                        description=f"Control-flow nesting reaches depth {depth}; class and method braces are excluded.",
                        severity="Medium",
                        severity_score=5.5,
                        language="java",
                        line=line,
                        column=0,
                        evidence=self._snippet(line),
                        risk_explanation="Deeply nested control flow can make execution paths harder to follow.",
                        mitigation="Consider guard clauses and extracting nested logic into methods.",
                        references=["https://en.wikipedia.org/wiki/Spaghetti_code"],
                        confidence="Medium",
                        category="Complexity"
                    )

        # 4. Method declarations and structural analysis
        method_matches = list(self.METHOD_RE.finditer(self.masked))
        class_matches = list(re.finditer(r"\bclass\s+([A-Za-z_$][\w$]*)", self.masked))
        class_names = {m.group(1) for m in class_matches}

        for match in method_matches:
            name = match.group(1)
            opening = self.masked.find("{", match.end() - 1)
            if opening == -1 or opening not in pairs:
                continue
            closing = pairs[opening]
            start_line = self._line_for_offset(self.masked, match.start())

            # Constructor names equal class name and should not be reported as method naming violations
            if name and name[0].isupper() and name not in class_names and name != "main":
                self._add(
                    rule_id="PRACTICE-JV-003",
                    title=f"Java Method Naming Convention Violation '{name}'",
                    description="Method name starts with an uppercase letter; Java methods conventionally use lowerCamelCase.",
                    severity="Informational",
                    severity_score=1.5,
                    language="java",
                    line=start_line,
                    column=0,
                    evidence=self._snippet(start_line),
                    risk_explanation="Inconsistent naming can confuse readers about whether a declaration is a method or type.",
                    mitigation="Consider renaming the method using lowerCamelCase.",
                    references=["https://google.github.io/styleguide/javaguide.html#s5.2.3-method-names"],
                    confidence="High",
                    category="Poor Coding Practice"
                )

            parameter_count = self._count_parameters(match.group(2))
            if parameter_count > 5:
                self._add(
                    rule_id="SMELL-JV-002",
                    title=f"Long Parameter List in Java Method '{name}()' ({parameter_count} parameters)",
                    description=f"Method has {parameter_count} parameters, above the review threshold of 5.",
                    severity="Low",
                    severity_score=3.0,
                    language="java",
                    line=start_line,
                    column=0,
                    evidence=self._snippet(start_line),
                    risk_explanation="Many parameters can make calls hard to understand and maintain.",
                    mitigation="Group related parameters into a suitable value object when that improves clarity.",
                    references=["https://refactoring.guru/smells/long-parameter-list"],
                    confidence="High",
                    category="Code Smell"
                )

            body = self.masked[opening + 1:closing]
            body_lines = self._line_for_offset(self.masked, closing) - self._line_for_offset(self.masked, opening)
            if body_lines > 50:
                self._add(
                    rule_id="SMELL-JV-001",
                    title=f"Long Java Method '{name}()'",
                    description=f"Method body spans approximately {body_lines} lines; review whether responsibilities can be separated.",
                    severity="Medium" if body_lines > 80 else "Low",
                    severity_score=5.0 if body_lines > 80 else 3.5,
                    language="java",
                    line=start_line,
                    column=0,
                    evidence=self._snippet(start_line),
                    risk_explanation="Long methods can accumulate unrelated behavior and become difficult to test.",
                    mitigation="Extract cohesive operations into smaller methods.",
                    references=["https://refactoring.guru/smells/long-method"],
                    confidence="Medium",
                    category="Code Smell"
                )

            complexity = 1 + len(re.findall(r"\b(?:if|for|while|case|catch)\b|\?|&&|\|\|", body))
            if complexity > 8:
                self._add(
                    rule_id="COMPLEX-JV-001",
                    title=f"High Cyclomatic Complexity in Java Method '{name}()' (CC ≈ {complexity})",
                    description=f"Estimated method complexity is {complexity}; this lightweight scanner uses a heuristic count of branch operators.",
                    severity="High" if complexity > 15 else "Medium",
                    severity_score=8.0 if complexity > 15 else 6.0,
                    language="java",
                    line=start_line,
                    column=0,
                    evidence=self._snippet(start_line),
                    risk_explanation="Many branch points increase the number of paths that may need tests.",
                    mitigation="Simplify conditions or extract cohesive branches into helper methods.",
                    references=["https://en.wikipedia.org/wiki/Cyclomatic_complexity"],
                    confidence="Low",
                    category="Complexity"
                )

        # 5. Class size based on actual class body, rather than whole source-file length
        for match in class_matches:
            opening = self.masked.find("{", match.end())
            if opening == -1 or opening not in pairs:
                continue
            closing = pairs[opening]
            lines = self._line_for_offset(self.masked, closing) - self._line_for_offset(self.masked, opening) + 1
            if lines > 200:
                self._add(
                    rule_id="SMELL-JV-003",
                    title=f"Large Java Class '{match.group(1)}'",
                    description=f"Class body spans approximately {lines} lines; review its responsibilities.",
                    severity="High" if lines > 300 else "Medium",
                    severity_score=7.0 if lines > 300 else 4.8,
                    language="java",
                    line=self._line_for_offset(self.masked, match.start()),
                    column=0,
                    evidence=self._snippet(self._line_for_offset(self.masked, match.start())),
                    risk_explanation="Large classes may have multiple responsibilities and be harder to maintain.",
                    mitigation="Split independent responsibilities into smaller, cohesive classes where appropriate.",
                    references=["https://refactoring.guru/smells/large-class"],
                    confidence="Medium",
                    category="Code Smell"
                )

        return self.findings


class CodeAnalysisAgent:
    """Entry point for deterministic code quality analysis of Python and Java."""

    def __init__(self):
        self.name = AGENT_NAME
        self.version = "2.0.0"

    def analyze(self, source_code: str, language: str, filename: Optional[str] = None) -> List[Finding]:
        if not isinstance(source_code, str) or not source_code.strip():
            return []
        lang = (language or "").strip().lower()
        if lang in {"python", "py", "python3"}:
            return self._analyze_python(source_code)
        if lang in {"java", "jav"}:
            return self._analyze_java(source_code)
        return []

    def _analyze_python(self, source_code: str) -> List[Finding]:
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            # Syntax validation belongs to the syntax-validation component.
            return []

        source_lines = source_code.splitlines()

        # Pre-scan with-context expressions so that multiline or nested With statements are 100% indexed
        with_context_calls: Set[ast.Call] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.With, getattr(ast, "AsyncWith", ast.With))):
                for item in node.items:
                    for child in ast.walk(item.context_expr):
                        if isinstance(child, ast.Call):
                            with_context_calls.add(child)

        visitor = PythonCodeAnalysisVisitor(source_lines=source_lines, with_context_calls=with_context_calls)
        visitor.visit(tree)
        return visitor.findings

    def _analyze_java(self, source_code: str) -> List[Finding]:
        scanner = JavaCodeAnalysisScanner(source_code)
        return scanner.scan()
