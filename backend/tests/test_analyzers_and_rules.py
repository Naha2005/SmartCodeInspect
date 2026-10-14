import pytest
from analyzers.python_analyzer import analyze_python_source
from analyzers.java_analyzer import analyze_java_source


def test_python_safe_source_produces_no_findings():
    safe_code = """
import json

def process_data(payload):
    data = json.loads(payload)
    items = [x * 2 for x in data.get('numbers', [])]
    return {'result': items}
"""
    res = analyze_python_source(safe_code, filename="safe_app.py")
    assert res["valid_syntax"] is True
    assert res["summary"]["total_findings"] == 0
    assert len(res["findings"]) == 0


def test_python_vulnerable_eval_exec():
    vuln_code = """
def run_user_input(untrusted_code):
    result = eval(untrusted_code)
    exec("print('done')")
    return result
"""
    res = analyze_python_source(vuln_code, filename="eval_vuln.py")
    assert res["valid_syntax"] is True
    assert res["summary"]["total_findings"] == 2
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "SEC-PY-001" in rule_ids
    assert res["findings"][0]["severity"] == "Critical"
    assert res["findings"][0]["line"] == 3


def test_python_vulnerable_subprocess_shell_true():
    vuln_code = """
import subprocess

def ping(host):
    subprocess.Popen("ping " + host, shell=True)
"""
    res = analyze_python_source(vuln_code, filename="cmd_vuln.py")
    assert res["valid_syntax"] is True
    assert any(f["rule_id"] == "SEC-PY-002" for f in res["findings"])


def test_python_vulnerable_sql_injection():
    vuln_code = """
def get_user(cursor, user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
"""
    res = analyze_python_source(vuln_code, filename="sql_vuln.py")
    assert res["valid_syntax"] is True
    assert any(f["rule_id"] == "SEC-PY-003" for f in res["findings"])


def test_python_vulnerable_hardcoded_secrets():
    vuln_code = """
api_key = "AIzaSyD-fake-secret-key-12345"
db_password = "SuperSecretPassword123!"
"""
    res = analyze_python_source(vuln_code, filename="secrets_vuln.py")
    assert res["valid_syntax"] is True
    secret_findings = [f for f in res["findings"] if f["rule_id"] == "SEC-PY-004"]
    assert len(secret_findings) == 2


def test_python_vulnerable_pickle_deserialization():
    vuln_code = """
import pickle

def load_payload(raw_bytes):
    return pickle.loads(raw_bytes)
"""
    res = analyze_python_source(vuln_code, filename="pickle_vuln.py")
    assert res["valid_syntax"] is True
    assert any(f["rule_id"] == "SEC-PY-005" for f in res["findings"])


def test_python_vulnerable_weak_hash_md5():
    vuln_code = """
import hashlib

def hash_token(data):
    return hashlib.md5(data.encode()).hexdigest()
"""
    res = analyze_python_source(vuln_code, filename="md5_vuln.py")
    assert res["valid_syntax"] is True
    assert any(f["rule_id"] == "SEC-PY-006" for f in res["findings"])


def test_java_safe_source_produces_no_findings():
    safe_code = """
import java.security.MessageDigest;

public class SafeHasher {
    public static byte[] hash(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input);
    }
}
"""
    res = analyze_java_source(safe_code, filename="SafeHasher.java")
    assert res["valid_syntax"] is True
    assert res["summary"]["total_findings"] == 0


def test_java_vulnerable_sql_injection():
    vuln_code = """
import java.sql.*;

public class UserRepo {
    public void findUser(Statement stmt, String username) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + username + "'");
    }
}
"""
    res = analyze_java_source(vuln_code, filename="UserRepo.java")
    assert res["valid_syntax"] is True
    assert any(f["rule_id"] == "SEC-JV-001" for f in res["findings"])


def test_java_vulnerable_command_execution():
    vuln_code = """
public class Executor {
    public void run(String cmd) throws Exception {
        Runtime.getRuntime().exec("sh -c " + cmd);
    }
}
"""
    res = analyze_java_source(vuln_code, filename="Executor.java")
    assert res["valid_syntax"] is True
    assert any(f["rule_id"] == "SEC-JV-002" for f in res["findings"])


def test_java_vulnerable_hardcoded_secrets():
    vuln_code = """
public class Config {
    private String apiKey = "secret_live_token_987654";
    public String password = "ProductionAdminPassword!";
}
"""
    res = analyze_java_source(vuln_code, filename="Config.java")
    assert res["valid_syntax"] is True
    secret_findings = [f for f in res["findings"] if f["rule_id"] == "SEC-JV-003"]
    assert len(secret_findings) >= 2


def test_java_vulnerable_deserialization():
    vuln_code = """
import java.io.*;

public class Deserializer {
    public Object deserialize(InputStream is) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(is);
        return ois.readObject();
    }
}
"""
    res = analyze_java_source(vuln_code, filename="Deserializer.java")
    assert res["valid_syntax"] is True
    assert any(f["rule_id"] == "SEC-JV-004" for f in res["findings"])


def test_java_vulnerable_weak_crypto_md5():
    vuln_code = """
import java.security.MessageDigest;

public class LegacyHash {
    public void hashData() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
    }
}
"""
    res = analyze_java_source(vuln_code, filename="LegacyHash.java")
    assert res["valid_syntax"] is True
    assert any(f["rule_id"] == "SEC-JV-005" for f in res["findings"])
