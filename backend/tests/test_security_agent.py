import pytest
from agents.security_agent import SecurityVulnerabilityAgent


@pytest.fixture
def agent():
    return SecurityVulnerabilityAgent()


PYTHON_VULNERABLE_CODE = """import os
import subprocess
import pickle
import hashlib
import sqlite3
import requests

API_SECRET_KEY = "AIzaSyD-super-secret-production-token-99"
DB_PASS = "SuperSecretPassword123!"

def vulnerable_operations(user_input, target_url, file_path):
    # OWASP A03: Injection - Dynamic eval RCE
    res = eval(user_input)
    
    # OWASP A03: Injection - Command injection shell=True
    subprocess.Popen("ping -c 1 " + user_input, shell=True)
    
    # OWASP A03: Injection - SQL injection via dynamic query
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    
    # OWASP A08: Software & Data Integrity Failures - Pickle deserialization
    obj = pickle.loads(user_input)
    
    # OWASP A02: Cryptographic Failures - Weak MD5 hash
    h = hashlib.md5(user_input.encode()).hexdigest()
    
    # OWASP A01: Broken Access Control - Path Traversal
    full_path = os.path.join("/var/data", user_input)
    
    # OWASP A10: Server-Side Request Forgery (SSRF)
    resp = requests.get(target_url)
    
    return res
"""

PYTHON_SECURE_CODE = """import hashlib
import subprocess
import sqlite3
import json

def secure_operations(user_id: int):
    # Parameterized SQL query
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    
    # Secure SHA-256 hash
    h = hashlib.sha256(str(user_id).encode("utf-8")).hexdigest()
    
    # Safe JSON deserialization
    data = json.loads('{"id": 123}')
    
    # Safe subprocess without shell=True
    subprocess.run(["echo", "hello"], shell=False, check=True)
    
    return h
"""

JAVA_VULNERABLE_CODE = """import java.io.*;
import java.sql.*;
import java.security.MessageDigest;
import javax.xml.parsers.DocumentBuilderFactory;

public class VulnerableEnterprisePortal {
    // OWASP A07: Hardcoded secret
    private static final String AWS_SECRET = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY";
    private static final String DB_PASSWORD = "RootAdminPassword_2026";

    public void processPayment(Connection conn, String user, String scriptName, String userFile) throws Exception {
        Statement stmt = conn.createStatement();
        // OWASP A03: SQL Injection via query concatenation
        String query = "SELECT * FROM accounts WHERE user = '" + user + "'";
        stmt.executeQuery(query);

        // OWASP A03: Command Injection via Runtime.getRuntime().exec()
        Runtime.getRuntime().exec("sh /opt/scripts/" + scriptName);

        // OWASP A08: Insecure Deserialization via ObjectInputStream
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data.bin"));
        Object obj = ois.readObject();

        // OWASP A02: Cryptographic Failures - Weak MD5
        MessageDigest md = MessageDigest.getInstance("MD5");

        // OWASP A01: Path Traversal via dynamic File constructor
        File f = new File("/safe/dir", userFile);

        // OWASP A05: Insecure XML Parser (XXE)
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    }
}
"""

JAVA_SECURE_CODE = """import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

public class SecureEnterprisePortal {
    public void queryAccount(Connection conn, int userId) throws Exception {
        // Safe Parameterized PreparedStatement
        String sql = "SELECT * FROM accounts WHERE id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, userId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    // process
                }
            }
        }
    }

    public byte[] computeSecureHash(String data) throws Exception {
        // Safe SHA-256 hash
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data.getBytes(StandardCharsets.UTF_8));
    }
}
"""


def test_python_owasp_vulnerabilities_detected(agent):
    findings = agent.analyze(PYTHON_VULNERABLE_CODE, language="python")
    rule_ids = {f.rule_id for f in findings}

    # Verify RCE via eval() (SEC-PY-001)
    assert "SEC-PY-001" in rule_ids, "Should detect eval() RCE (OWASP A03)"

    # Verify OS Command Injection (SEC-PY-002)
    assert "SEC-PY-002" in rule_ids, "Should detect OS Command Injection (OWASP A03)"

    # Verify SQL Injection (SEC-PY-003)
    assert "SEC-PY-003" in rule_ids, "Should detect SQL Injection (OWASP A03)"

    # Verify Hardcoded secrets (SEC-PY-004)
    assert "SEC-PY-004" in rule_ids, "Should detect Hardcoded Secrets (OWASP A07)"

    # Verify Insecure Deserialization (SEC-PY-005)
    assert "SEC-PY-005" in rule_ids, "Should detect Pickle Insecure Deserialization (OWASP A08)"

    # Verify Weak Cryptographic Hash (SEC-PY-006)
    assert "SEC-PY-006" in rule_ids, "Should detect Weak MD5 Hash (OWASP A02)"

    # Verify Path Traversal (SEC-PY-007)
    assert "SEC-PY-007" in rule_ids, "Should detect Path Traversal (OWASP A01)"

    # Verify SSRF (SEC-PY-008)
    assert "SEC-PY-008" in rule_ids, "Should detect SSRF (OWASP A10)"


def test_python_location_flagging_and_scoring(agent):
    findings = agent.analyze(PYTHON_VULNERABLE_CODE, language="python")

    for f in findings:
        assert f.line > 0, "Line number must be positive integer"
        assert f.evidence, "Evidence snippet must not be empty"
        assert f.severity in ("Critical", "High", "Medium", "Low"), "Severity must be valid"
        assert f.severity_score >= 5.0, "All major security findings must have severity_score >= 5.0"
        assert f.agent == "Security Vulnerability Agent"
        assert f.category == "Security Vulnerability"
        assert f.cwe_id.startswith("CWE-"), f"CWE ID must be populated, got: {f.cwe_id}"
        assert f.owasp_category != "", "OWASP category must be assigned"
        assert len(f.owasp_references) > 0, "OWASP references must be provided"


def test_java_owasp_vulnerabilities_detected(agent):
    findings = agent.analyze(JAVA_VULNERABLE_CODE, language="java")
    rule_ids = {f.rule_id for f in findings}

    # Verify SQL Injection via concatenation (SEC-JV-001)
    assert "SEC-JV-001" in rule_ids, "Should detect Java SQL Injection"

    # Verify OS Command Injection (SEC-JV-002)
    assert "SEC-JV-002" in rule_ids, "Should detect Java Runtime.exec Command Injection"

    # Verify Hardcoded Secrets (SEC-JV-003)
    assert "SEC-JV-003" in rule_ids, "Should detect Java Hardcoded Secrets"

    # Verify Insecure Deserialization (SEC-JV-004)
    assert "SEC-JV-004" in rule_ids, "Should detect Java Insecure Deserialization"

    # Verify Weak Cryptography (SEC-JV-005)
    assert "SEC-JV-005" in rule_ids, "Should detect Java Weak MD5"

    # Verify Path Traversal (SEC-JV-006)
    assert "SEC-JV-006" in rule_ids, "Should detect Java Path Traversal"

    # Verify XXE (SEC-JV-007)
    assert "SEC-JV-007" in rule_ids, "Should detect Java Insecure XML / XXE"


def test_secure_codebases_zero_false_positives(agent):
    py_findings = agent.analyze(PYTHON_SECURE_CODE, language="python")
    assert len(py_findings) == 0, f"Secure Python code should have 0 security findings, got: {[f.rule_id for f in py_findings]}"

    jv_findings = agent.analyze(JAVA_SECURE_CODE, language="java")
    assert len(jv_findings) == 0, f"Secure Java code should have 0 security findings, got: {[f.rule_id for f in jv_findings]}"


def test_user_specified_cases_ssrf_and_path_traversal(agent):
    # 1. Python code using requests.get(user_url) -> Potential SSRF finding
    code_ssrf_dynamic = """import requests
def fetch(user_url):
    return requests.get(user_url)
"""
    f_ssrf = agent.analyze(code_ssrf_dynamic, language="python")
    assert any(f.rule_id == "SEC-PY-008" for f in f_ssrf), "Should detect SSRF with dynamic URL"

    # 2. Python code using a constant URL -> No SSRF finding from this heuristic
    code_ssrf_constant = """import requests
def fetch_safe():
    return requests.get("https://api.github.com/zen")
"""
    f_safe_url = agent.analyze(code_ssrf_constant, language="python")
    assert not any(f.rule_id == "SEC-PY-008" for f in f_safe_url), "Should not flag constant URL as SSRF"

    # 3. Python file access using a dynamic path -> Potential path traversal finding
    code_path_dynamic = """def read_custom_doc(dynamic_target):
    with open(dynamic_target, "r") as fh:
        return fh.read()
"""
    f_path = agent.analyze(code_path_dynamic, language="python")
    assert any(f.rule_id == "SEC-PY-007" for f in f_path), "Should detect path traversal with dynamic path"

    # 4. Java file constructor using a variable named filename -> Potential path traversal finding
    code_java_path = """public class DocLoader {
    public void openDoc(String filename) {
        java.io.File f = new java.io.File(filename);
    }
}
"""
    f_jv_path = agent.analyze(code_java_path, language="java")
    assert any(f.rule_id == "SEC-JV-006" for f in f_jv_path), "Should detect Java path traversal"

    # 5. Java XML factory without nearby protection markers -> Potential XXE finding
    code_java_xxe_unsafe = """import javax.xml.parsers.DocumentBuilderFactory;
public class XmlReader {
    public void read() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // No security configuration
    }
}
"""
    f_jv_xxe = agent.analyze(code_java_xxe_unsafe, language="java")
    assert any(f.rule_id == "SEC-JV-007" for f in f_jv_xxe), "Should detect Java XXE without protection"

    # 6. Java XML factory with an obvious protection marker nearby -> Heuristic suppresses XXE
    code_java_xxe_safe = """import javax.xml.parsers.DocumentBuilderFactory;
public class SafeXmlReader {
    public void read() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    }
}
"""
    f_jv_xxe_safe = agent.analyze(code_java_xxe_safe, language="java")
    assert not any(f.rule_id == "SEC-JV-007" for f in f_jv_xxe_safe), "Should suppress XXE finding when protection marker is nearby"

    # 7. Invalid Python syntax -> Security visitor skips analysis and returns empty findings
    code_invalid_syntax = "def broken_code(:\n    pass"
    f_invalid = agent.analyze(code_invalid_syntax, language="python")
    assert f_invalid == [], "Security visitor should skip and return empty findings on invalid syntax"


def test_syntax_error_reported_clearly():
    from validators.python_validator import validate_python_source
    from analyzers.python_analyzer import analyze_python_source

    code_invalid = "def syntax_failure(:\n    return 42"
    val_res = validate_python_source(code_invalid)
    assert val_res["valid_syntax"] is False
    assert len(val_res["diagnostics"]) > 0

    analysis_res = analyze_python_source(code_invalid)
    assert analysis_res["valid_syntax"] is False
    assert analysis_res["summary"]["security_posture"] == "N/A (Syntax Error)"
    assert len(analysis_res["diagnostics"]) > 0

