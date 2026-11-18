"""
Sample 3: High Complexity (OWASP Security Vulnerabilities)
Language: Python
Purpose: Demonstrates severe security flaws across OWASP Top 10 (2021/2026).
Flagged Rules:
- SEC-PY-001 (Arbitrary Code Execution via eval)
- SEC-PY-002 (OS Command Injection via subprocess shell=True)
- SEC-PY-003 (SQL Injection via direct string formatting)
- SEC-PY-004 (Hardcoded secrets / credentials)
- SEC-PY-005 (Insecure Deserialization via pickle)
- SEC-PY-007 (Broken Cryptographic Hashing via MD5)
- RISK-PY-001 (Missing timeout on network requests)
"""

import os
import subprocess
import pickle
import hashlib
import sqlite3
import requests

# Vulnerability 1: Hardcoded credentials in source code
API_SECRET_KEY = "AIzaSyD-untrusted-production-key-999"
DB_PASS = "SuperSecretPassword123!"


def process_user_query(user_param: str):
    # Vulnerability 2: Arbitrary code execution via dynamic eval()
    evaluated = eval(user_param)

    # Vulnerability 3: OS Command Injection via shell=True
    subprocess.Popen("ping -c 1 " + user_param, shell=True)

    # Vulnerability 4: SQL Injection via direct unescaped string formatting
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM accounts WHERE username = '{user_param}'")

    # Vulnerability 5: Unmanaged network call missing timeout parameter (CWE-400)
    resp = requests.get("https://api.example.com/status?user=" + user_param)

    return evaluated


def deserialize_state(untrusted_stream: bytes):
    # Vulnerability 6: Insecure Deserialization via pickle
    return pickle.loads(untrusted_stream)


def hash_user_password(password: str) -> str:
    # Vulnerability 7: Weak broken cryptographic hash (MD5)
    return hashlib.md5(password.encode()).hexdigest()
