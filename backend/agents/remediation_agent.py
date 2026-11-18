"""
Remediation Agent for Smart Code Inspection Platform.

Generates specific, actionable fix recommendations with corrected code examples,
best practice explanations, and before/after comparisons for each flagged finding.
Handles both Python and Java source code across OWASP security vulnerabilities,
code smells, complexity issues, design anti-patterns, and poor practices.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

AGENT_NAME = "Remediation Agent"

# Deterministic Remediation Knowledge Catalog
REMEDIATION_CATALOG: Dict[str, Dict[str, Any]] = {
    # -------------------------------------------------------------
    # Python Security Vulnerabilities
    # -------------------------------------------------------------
    "SEC-PY-001": {
        "title": "Replace Dynamic eval() / exec() with Safe Parsers or Explicit Logic",
        "recommendation": (
            "Never evaluate untrusted input with eval() or exec(). Replace with ast.literal_eval() "
            "for parsing literal data structures (strings, numbers, tuples, lists, dicts, booleans, None), "
            "or implement an explicit dictionary dispatch table / operator mapping."
        ),
        "corrected_code": (
            "# Safe evaluation using ast.literal_eval for safe literals\n"
            "import ast\n\n"
            "def safe_calculate(expr_str: str):\n"
            "    # Only parses safe literals (strings, numbers, tuples, lists, dicts, booleans, None)\n"
            "    try:\n"
            "        return ast.literal_eval(expr_str)\n"
            "    except (ValueError, SyntaxError) as err:\n"
            "        raise ValueError(f'Invalid or unsupported literal: {err}')\n\n"
            "# For mathematical expressions, use a structured operator dispatch:\n"
            "import operator\n"
            "OPERATORS = {'+': operator.add, '-': operator.sub, '*': operator.mul, '/': operator.truediv}\n"
            "def compute(op: str, a: float, b: float) -> float:\n"
            "    if op not in OPERATORS:\n"
            "        raise ValueError(f'Unsupported operator: {op}')\n"
            "    return OPERATORS[op](a, b)"
        ),
        "explanation": (
            "eval() executes arbitrary Python code in the current execution context. An attacker "
            "supplying '__import__(\"os\").system(\"...\")' gains full remote code execution (RCE). "
            "ast.literal_eval() is safe because it only parses primitive Python literal structures "
            "and does not execute functions, method calls, or module imports."
        ),
        "best_practices": [
            "OWASP A03:2021 - Prevent Injection by avoiding dynamic code execution",
            "Use ast.literal_eval() when evaluating serialized literal values",
            "Use explicit whitelist dispatch tables instead of dynamic function invocation",
            "Sanitize and validate all user-controlled inputs before parsing"
        ],
        "diff_example": (
            "# BEFORE (VULNERABLE):\n"
            "# result = eval(user_input)\n\n"
            "# AFTER (REMEDIATED):\n"
            "import ast\n"
            "try:\n"
            "    result = ast.literal_eval(user_input)\n"
            "except (ValueError, SyntaxError):\n"
            "    result = None"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
            "https://docs.python.org/3/library/ast.html#ast.literal_eval",
            "https://cwe.mitre.org/data/definitions/95.html"
        ]
    },

    "SEC-PY-002": {
        "title": "Use subprocess.run with Argument List and shell=False",
        "recommendation": (
            "Never invoke shell interpreters with shell=True or string concatenation. Use subprocess.run() "
            "passing arguments as a list of strings with shell=False (default). If arguments must be quoted, "
            "use shlex.quote() or shlex.split()."
        ),
        "corrected_code": (
            "import subprocess\n"
            "import shlex\n\n"
            "def run_system_task(target_path: str) -> subprocess.CompletedProcess:\n"
            "    # Pass program and arguments as an explicit list; shell=False prevents shell metacharacter expansion\n"
            "    cmd = ['ls', '-la', target_path]\n"
            "    result = subprocess.run(\n"
            "        cmd,\n"
            "        capture_output=True,\n"
            "        text=True,\n"
            "        check=True,\n"
            "        timeout=10.0  # Enforce execution timeout\n"
            "    )\n"
            "    return result"
        ),
        "explanation": (
            "Passing shell=True or using os.system() causes the Python runtime to pass the raw string "
            "to the operating system shell (/bin/sh or cmd.exe). Metacharacters like ';', '&&', '|', or '$()' "
            "allow attackers to chain malicious arbitrary commands. Passing an argument list to subprocess.run "
            "invokes the binary directly via execve, treating arguments as pure data without shell expansion."
        ),
        "best_practices": [
            "OWASP A03:2021 - OS Command Injection Prevention",
            "Always set shell=False and pass command as List[str]",
            "Enforce timeouts with timeout parameter to prevent hanging processes",
            "Use check=True to handle non-zero exit codes predictably"
        ],
        "diff_example": (
            "# BEFORE (VULNERABLE):\n"
            "# subprocess.Popen('cat ' + filename, shell=True)\n\n"
            "# AFTER (REMEDIATED):\n"
            "subprocess.run(['cat', filename], check=True, capture_output=True, text=True)"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://docs.python.org/3/library/subprocess.html",
            "https://cwe.mitre.org/data/definitions/78.html"
        ]
    },

    "SEC-PY-003": {
        "title": "Use Parameterized Queries / Prepared Statements for Database Access",
        "recommendation": (
            "Never interpolate, format, or concatenate user-controlled strings into SQL statements. "
            "Use parameterized queries with placeholder markers ('?' for sqlite3, '%s' for psycopg2/PyMySQL) "
            "or an ORM like SQLAlchemy."
        ),
        "corrected_code": (
            "import sqlite3\n\n"
            "def get_user_by_username(db_path: str, username: str):\n"
            "    with sqlite3.connect(db_path) as conn:\n"
            "        cursor = conn.cursor()\n"
            "        # Parameterized query: '?' placeholder treats input strictly as literal data\n"
            "        query = 'SELECT id, username, email, role FROM users WHERE username = ? AND is_active = 1'\n"
            "        cursor.execute(query, (username,))\n"
            "        return cursor.fetchone()"
        ),
        "explanation": (
            "String formatting (f-strings, %, .format()) mixes SQL code with untrusted data before parsing. "
            "An attacker can inject SQL syntax (e.g. \"' OR '1'='1\") to alter query logic, bypass authentication, "
            "or dump database tables. Parameterized queries send query structure and data values separately, "
            "preventing data from ever being interpreted as SQL commands."
        ),
        "best_practices": [
            "OWASP A03:2021 - SQL Injection Prevention Cheat Sheet",
            "Always use query placeholders ('?' or '%s') - never format SQL strings",
            "Use object-relational mappers (SQLAlchemy, Django ORM) with parameterized filtering",
            "Enforce the principle of least privilege on database connection credentials"
        ],
        "diff_example": (
            "# BEFORE (VULNERABLE):\n"
            "# cursor.execute(f'SELECT * FROM users WHERE username = \"{user_input}\"')\n\n"
            "# AFTER (REMEDIATED):\n"
            "cursor.execute('SELECT * FROM users WHERE username = ?', (user_input,))"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://docs.python.org/3/library/sqlite3.html",
            "https://cwe.mitre.org/data/definitions/89.html"
        ]
    },

    "SEC-PY-004": {
        "title": "Extract Hardcoded Secrets into Environment Variables or Secret Vault",
        "recommendation": (
            "Remove all hardcoded API keys, tokens, passwords, and private keys from source code. "
            "Fetch credentials at runtime using os.environ.get(), a .env configuration loader "
            "(e.g. python-dotenv), or a dedicated secret management service (AWS Secrets Manager, HashiCorp Vault)."
        ),
        "corrected_code": (
            "import os\n"
            "from typing import Optional\n\n"
            "def get_database_password() -> str:\n"
            "    # Read sensitive credentials from environment variable\n"
            "    secret = os.environ.get('DB_PASSWORD')\n"
            "    if not secret:\n"
            "        raise RuntimeError('Required environment variable DB_PASSWORD is not configured.')\n"
            "    return secret\n\n"
            "# For local development, load from untracked .env file:\n"
            "# from dotenv import load_dotenv\n"
            "# load_dotenv()  # Reads .env (ensure .env is listed in .gitignore)"
        ),
        "explanation": (
            "Hardcoded secrets embedded in source code are committed into revision control systems (Git), "
            "leaking into repository clones, CI/CD build logs, and third-party integrations. Attackers "
            "scan public and leaked repositories for credential tokens to breach cloud infrastructure."
        ),
        "best_practices": [
            "OWASP A07:2021 - Secrets Management Cheat Sheet",
            "Never commit .env, private keys, or API tokens into source control",
            "Include .env, *.pem, *.key, and credentials.json in .gitignore",
            "Rotate any secrets that have ever been committed to source history"
        ],
        "diff_example": (
            "# BEFORE (VULNERABLE):\n"
            "# API_KEY = 'AKIA-PRODUCTION-SECRET-KEY-12345'\n\n"
            "# AFTER (REMEDIATED):\n"
            "API_KEY = os.environ.get('API_KEY')\n"
            "if not API_KEY:\n"
            "    raise EnvironmentError('API_KEY environment variable missing')"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/798.html"
        ]
    },

    "SEC-PY-005": {
        "title": "Replace Insecure Deserialization (pickle) with Safe Serialization Formats",
        "recommendation": (
            "Avoid pickle for deserializing untrusted data. Use standard, safe data interchange "
            "formats such as JSON, Protocol Buffers, or MessagePack. If complex objects must be reconstructed, "
            "validate input payloads against a strict schema (e.g. pydantic or marshmallow)."
        ),
        "corrected_code": (
            "import json\n"
            "from typing import Dict, Any\n\n"
            "def parse_user_payload(raw_json_str: str) -> Dict[str, Any]:\n"
            "    # JSON parses safe data structures without arbitrary class instantiation\n"
            "    try:\n"
            "        data = json.loads(raw_json_str)\n"
            "    except json.JSONDecodeError as err:\n"
            "        raise ValueError(f'Invalid JSON payload: {err}')\n\n"
            "    # Enforce strict field schema validation\n"
            "    if not isinstance(data, dict) or 'user_id' not in data:\n"
            "        raise ValueError('Missing required payload fields.')\n"
            "    return data"
        ),
        "explanation": (
            "Python's pickle module is fundamentally unsafe for untrusted input. An attacker can craft "
            "a serialized payload containing a custom __reduce__ method that executes arbitrary OS commands "
            "immediately upon pickle.loads(), leading to full remote code execution without needing any bugs "
            "in the surrounding code."
        ),
        "best_practices": [
            "OWASP A08:2021 - Deserialization Cheat Sheet",
            "Never use pickle.load() or pickle.loads() on network-received or untrusted data",
            "Use json.loads() for structured text and validate with schema validators (Pydantic)",
            "Sign serialized payloads with HMAC-SHA256 if binary serialization is unavoidable internally"
        ],
        "diff_example": (
            "# BEFORE (VULNERABLE):\n"
            "# obj = pickle.loads(untrusted_stream)\n\n"
            "# AFTER (REMEDIATED):\n"
            "import json\n"
            "obj = json.loads(untrusted_stream.decode('utf-8'))"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
            "https://docs.python.org/3/library/pickle.html",
            "https://cwe.mitre.org/data/definitions/502.html"
        ]
    },

    "SEC-PY-006": {
        "title": "Upgrade Deprecated Hashes (MD5/SHA1) to SHA-256 or Secure Password Hashing",
        "recommendation": (
            "MD5 and SHA-1 are cryptographically broken and vulnerable to collision attacks. "
            "For general integrity and digest checks, upgrade to hashlib.sha256() or hashlib.sha512(). "
            "For user passwords, never use raw fast cryptographic hashes; use dedicated salted, "
            "work-factored algorithms such as bcrypt, argon2-cffi, or hashlib.pbkdf2_hmac()."
        ),
        "corrected_code": (
            "import hashlib\n\n"
            "# For document or file checksums (integrity verification):\n"
            "def calculate_file_sha256(data: bytes) -> str:\n"
            "    return hashlib.sha256(data).hexdigest()\n\n"
            "# For password storage (slow, work-factored, salted):\n"
            "import secrets\n"
            "def hash_password_securely(password: str) -> tuple[bytes, bytes]:\n"
            "    salt = secrets.token_bytes(16)\n"
            "    key = hashlib.pbkdf2_hmac(\n"
            "        'sha256',\n"
            "        password.encode('utf-8'),\n"
            "        salt,\n"
            "        iterations=600000\n"
            "    )\n"
            "    return salt, key"
        ),
        "explanation": (
            "MD5 and SHA-1 suffer from practical collision attacks where two different inputs yield the same "
            "digest hash. Furthermore, because fast hashes can calculate billions of guesses per second on GPUs, "
            "using MD5/SHA-1 for passwords allows trivial rainbow table and brute-force cracking."
        ),
        "best_practices": [
            "OWASP A02:2021 - Cryptographic Storage Cheat Sheet",
            "Use SHA-256 / SHA-512 for data integrity and checksums",
            "Use Argon2id, bcrypt, or PBKDF2 with >= 600,000 iterations for password hashing",
            "Never implement custom cryptographic hashing routines"
        ],
        "diff_example": (
            "# BEFORE (VULNERABLE):\n"
            "# digest = hashlib.md5(content).hexdigest()\n\n"
            "# AFTER (REMEDIATED):\n"
            "digest = hashlib.sha256(content).hexdigest()"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/327.html"
        ]
    },

    "SEC-PY-007": {
        "title": "Prevent Path Traversal with Strict Path Containment and Whitelisting",
        "recommendation": (
            "Validate and normalize target file paths using pathlib.Path.resolve() and verify "
            "containment within an allowed base directory using Path.is_relative_to(). Disallow "
            "leading slashes and '..' sequences, or map user input to an explicit allowlist."
        ),
        "corrected_code": (
            "from pathlib import Path\n\n"
            "BASE_DIRECTORY = Path('/var/app/data').resolve()\n\n"
            "def get_safe_file_path(user_supplied_filename: str) -> Path:\n"
            "    # 1. Strip leading slashes and directory components\n"
            "    filename = Path(user_supplied_filename).name\n"
            "    target = (BASE_DIRECTORY / filename).resolve()\n\n"
            "    # 2. Strict containment check to prevent directory escape\n"
            "    if not target.is_relative_to(BASE_DIRECTORY):\n"
            "        raise PermissionError('Access denied: Path escapes designated boundary.')\n\n"
            "    return target"
        ),
        "explanation": (
            "When user input is combined with a base directory using os.path.join(), attackers can "
            "provide sequences like '../../etc/passwd'. If the path is not strictly validated, the system "
            "resolves above the intended root, allowing unauthorized reading or writing of arbitrary files."
        ),
        "best_practices": [
            "OWASP A01:2021 - Path Traversal Prevention",
            "Resolve absolute paths and test containment with is_relative_to()",
            "Extract only the basename via Path(filename).name to strip directory paths",
            "Operate with a dedicated service account having minimal filesystem privileges"
        ],
        "diff_example": (
            "# BEFORE (VULNERABLE):\n"
            "# target = os.path.join(BASE_DIR, user_input)\n\n"
            "# AFTER (REMEDIATED):\n"
            "target = (BASE_DIR / Path(user_input).name).resolve()\n"
            "if not target.is_relative_to(BASE_DIR):\n"
            "    raise ValueError('Path traversal attempt detected')"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/22.html"
        ]
    },

    "SEC-PY-008": {
        "title": "Protect Against Server-Side Request Forgery (SSRF) with URL Validation and IP Blocking",
        "recommendation": (
            "Validate outbound destination URLs against a strict whitelist of schemes ('https') and domain names. "
            "Resolve the target hostname and reject loopback (127.0.0.1, ::1), private subnets (10.0.0.0/8, "
            "172.16.0.0/12, 192.168.0.0/16), and cloud metadata endpoints (169.254.169.254)."
        ),
        "corrected_code": (
            "import ipaddress\n"
            "import socket\n"
            "from urllib.parse import urlparse\n"
            "import requests\n\n"
            "ALLOWED_DOMAINS = {'api.trusted-partner.com', 'services.example.com'}\n\n"
            "def safe_fetch(user_url: str) -> requests.Response:\n"
            "    parsed = urlparse(user_url)\n"
            "    if parsed.scheme != 'https':\n"
            "        raise ValueError('Only HTTPS URLs are permitted.')\n"
            "    if parsed.hostname not in ALLOWED_DOMAINS:\n"
            "        raise ValueError(f'Destination domain {parsed.hostname} is not in the allowlist.')\n\n"
            "    # Resolve IP and verify it is globally reachable\n"
            "    ip = socket.gethostbyname(parsed.hostname)\n"
            "    ip_addr = ipaddress.ip_address(ip)\n"
            "    if ip_addr.is_private or ip_addr.is_loopback or ip_addr.is_link_local:\n"
            "        raise ValueError('Access to internal network addresses is forbidden.')\n\n"
            "    return requests.get(user_url, timeout=5.0, allow_redirects=False)"
        ),
        "explanation": (
            "Server-Side Request Forgery occurs when a web server fetches a remote resource without "
            "verifying the destination. Attackers target localhost and cloud metadata services "
            "(169.254.169.254) to steal IAM credentials, internal database dumps, or cluster secrets."
        ),
        "best_practices": [
            "OWASP A10:2021 - Server-Side Request Forgery Prevention Cheat Sheet",
            "Enforce strict HTTPS scheme and whitelist allowed destination hostnames",
            "Disable HTTP redirects (allow_redirects=False) to avoid redirect-based SSRF bypasses",
            "Block private RFC 1918 subnets and cloud metadata IP addresses"
        ],
        "diff_example": (
            "# BEFORE (VULNERABLE):\n"
            "# requests.get(user_supplied_url)\n\n"
            "# AFTER (REMEDIATED):\n"
            "if urlparse(user_url).hostname in ALLOWED_HOSTS:\n"
            "    requests.get(user_url, timeout=5.0, allow_redirects=False)"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/918.html"
        ]
    },

    # -------------------------------------------------------------
    # Java Security Vulnerabilities
    # -------------------------------------------------------------
    "SEC-JV-001": {
        "title": "Use JDBC PreparedStatement with '?' Parameter Placeholders",
        "recommendation": (
            "Never construct SQL queries via string concatenation (+) or formatting. Use "
            "java.sql.PreparedStatement with '?' placeholders to bind parameters safely."
        ),
        "corrected_code": (
            "import java.sql.Connection;\n"
            "import java.sql.PreparedStatement;\n"
            "import java.sql.ResultSet;\n"
            "import java.sql.SQLException;\n\n"
            "public class UserRepository {\n"
            "    public User findUser(Connection conn, String username) throws SQLException {\n"
            "        String sql = \"SELECT id, username, email FROM users WHERE username = ? AND active = 1\";\n"
            "        try (PreparedStatement pstmt = conn.prepareStatement(sql)) {\n"
            "            pstmt.setString(1, username); // Safe parameter binding\n"
            "            try (ResultSet rs = pstmt.executeQuery()) {\n"
            "                if (rs.next()) {\n"
            "                    return new User(rs.getLong(\"id\"), rs.getString(\"username\"), rs.getString(\"email\"));\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "        return null;\n"
            "    }\n"
            "}"
        ),
        "explanation": (
            "Concatenating strings into executeQuery() allows an attacker to inject SQL operators and "
            "subqueries, altering the execution tree of the database engine. PreparedStatement pre-compiles "
            "the SQL command structure; bound parameters are treated strictly as literal data."
        ),
        "best_practices": [
            "OWASP A03:2021 - SQL Injection Prevention Cheat Sheet",
            "Always use PreparedStatement with typed setter methods (setString, setInt)",
            "Employ try-with-resources to guarantee PreparedStatement and ResultSet closure",
            "Leverage JPA/Hibernate with named parameterized queries"
        ],
        "diff_example": (
            "// BEFORE (VULNERABLE):\n"
            "// Statement stmt = conn.createStatement();\n"
            "// ResultSet rs = stmt.executeQuery(\"SELECT * FROM users WHERE name = '\" + input + \"'\");\n\n"
            "// AFTER (REMEDIATED):\n"
            "String sql = \"SELECT * FROM users WHERE name = ?\";\n"
            "try (PreparedStatement pstmt = conn.prepareStatement(sql)) {\n"
            "    pstmt.setString(1, input);\n"
            "    try (ResultSet rs = pstmt.executeQuery()) { ... }\n"
            "}"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://docs.oracle.com/en/java/javase/17/docs/api/java.sql/java/sql/PreparedStatement.html",
            "https://cwe.mitre.org/data/definitions/89.html"
        ]
    },

    "SEC-JV-002": {
        "title": "Use ProcessBuilder with Strict Argument Lists (Avoid Runtime.exec)",
        "recommendation": (
            "Never pass concatenated shell command strings to Runtime.getRuntime().exec(). Use "
            "ProcessBuilder with an explicit List<String> of arguments, and avoid invoking system "
            "shells ('sh', 'bash', 'cmd.exe')."
        ),
        "corrected_code": (
            "import java.io.File;\n"
            "import java.io.IOException;\n"
            "import java.util.List;\n"
            "import java.util.concurrent.TimeUnit;\n\n"
            "public class SafeProcessExecutor {\n"
            "    public int runCommand(File targetDir, String fileName) throws IOException, InterruptedException {\n"
            "        // Arguments passed as separate list elements prevent shell injection\n"
            "        List<String> command = List.of(\"/usr/bin/pdfinfo\", fileName);\n"
            "        ProcessBuilder pb = new ProcessBuilder(command);\n"
            "        pb.directory(targetDir);\n"
            "        pb.redirectErrorStream(true);\n\n"
            "        Process process = pb.start();\n"
            "        boolean finished = process.waitFor(10, TimeUnit.SECONDS);\n"
            "        if (!finished) {\n"
            "            process.destroyForcibly();\n"
            "            throw new IOException(\"Process timed out after 10 seconds\");\n"
            "        }\n"
            "        return process.exitValue();\n"
            "    }\n"
            "}"
        ),
        "explanation": (
            "Runtime.getRuntime().exec(String) tokenizes command strings unpredictably. If a shell like "
            "'sh -c' is invoked with concatenated parameters, characters like '|', ';', and '$()' execute "
            "arbitrary shell commands with the rights of the Java application."
        ),
        "best_practices": [
            "OWASP A03:2021 - OS Command Injection Defense",
            "Use ProcessBuilder with List<String> instead of string concatenation",
            "Enforce execution timeouts using process.waitFor(timeout, unit)",
            "Prefer pure Java standard libraries over spawning external processes"
        ],
        "diff_example": (
            "// BEFORE (VULNERABLE):\n"
            "// Runtime.getRuntime().exec(\"ping -c 1 \" + host);\n\n"
            "// AFTER (REMEDIATED):\n"
            "ProcessBuilder pb = new ProcessBuilder(\"ping\", \"-c\", \"1\", host);\n"
            "Process p = pb.start();"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/78.html"
        ]
    },

    "SEC-JV-003": {
        "title": "Extract Hardcoded Java Credentials to Environment Variables or Keystore",
        "recommendation": (
            "Never store passwords, secrets, or API keys in Java constants. Fetch them at runtime "
            "using System.getenv(), an externalized Spring application.properties file, or HashiCorp Vault."
        ),
        "corrected_code": (
            "import java.util.Optional;\n\n"
            "public class DatabaseConfig {\n"
            "    public static String getDatabasePassword() {\n"
            "        // Load sensitive credentials from system environment variables\n"
            "        String password = System.getenv(\"DB_PASSWORD\");\n"
            "        if (password == null || password.isBlank()) {\n"
            "            throw new IllegalStateException(\"Required environment variable 'DB_PASSWORD' is not set.\");\n"
            "        }\n"
            "        return password;\n"
            "    }\n"
            "}"
        ),
        "explanation": (
            "Hardcoded credentials in compiled .class or .jar files can be trivially extracted using standard "
            "decompilers (javap, CFR, Fernflower). Committing secrets to Git exposes infrastructure to leaks."
        ),
        "best_practices": [
            "OWASP A07:2021 - Identification and Authentication Failures",
            "Use System.getenv(\"VAR_NAME\") or Spring @Value(\"${VAR_NAME}\")",
            "Store secrets in enterprise vaults (AWS Secrets Manager, Azure Key Vault)",
            "Ensure credentials never appear in decompiled Java bytecode"
        ],
        "diff_example": (
            "// BEFORE (VULNERABLE):\n"
            "// private static final String DB_PASSWORD = \"SecretPass123!\";\n\n"
            "// AFTER (REMEDIATED):\n"
            "private static final String DB_PASSWORD = System.getenv(\"DB_PASSWORD\");"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/798.html"
        ]
    },

    "SEC-JV-004": {
        "title": "Enforce ObjectInputFilter Class Allowlisting for Java Deserialization",
        "recommendation": (
            "Java native serialization (ObjectInputStream.readObject) is prone to gadget chain RCE. "
            "Configure an ObjectInputFilter (JEP 290) allowlisting only trusted classes, or migrate "
            "to JSON (Jackson, Gson) with polymorphic type validation disabled."
        ),
        "corrected_code": (
            "import java.io.InputStream;\n"
            "import java.io.ObjectInputFilter;\n"
            "import java.io.ObjectInputStream;\n\n"
            "public class SecureDeserializer {\n"
            "    public static Object safeReadObject(InputStream is) throws Exception {\n"
            "        try (ObjectInputStream ois = new ObjectInputStream(is)) {\n"
            "            // Strict class allowlist filter rejects known gadget classes (CommonCollections, etc.)\n"
            "            ObjectInputFilter filter = filterInfo -> {\n"
            "                Class<?> serialClass = filterInfo.serialClass();\n"
            "                if (serialClass == null) return ObjectInputFilter.Status.UNDECIDED;\n"
            "                if (serialClass.getName().equals(\"com.example.SafeRecord\") ||\n"
            "                    serialClass.getName().equals(\"java.lang.String\")) {\n"
            "                    return ObjectInputFilter.Status.ALLOWED;\n"
            "                }\n"
            "                return ObjectInputFilter.Status.REJECTED;\n"
            "            };\n"
            "            ois.setObjectInputFilter(filter);\n"
            "            return ois.readObject();\n"
            "        }\n"
            "    }\n"
            "}"
        ),
        "explanation": (
            "Deserializing untrusted data with ObjectInputStream allows attackers to construct gadget chains "
            "using classes present in the application classpath (e.g. Apache Commons, Spring), triggering "
            "arbitrary code execution during the readObject() phase before the application inspects the object."
        ),
        "best_practices": [
            "OWASP A08:2021 - Java Deserialization Cheat Sheet",
            "Always configure ObjectInputFilter when using ObjectInputStream",
            "Prefer data-only formats (JSON, Protocol Buffers) over Java binary serialization",
            "Do not allow polymorphic types in JSON deserializers (e.g. Jackson enableDefaultTyping)"
        ],
        "diff_example": (
            "// BEFORE (VULNERABLE):\n"
            "// ObjectInputStream ois = new ObjectInputStream(is);\n"
            "// Object obj = ois.readObject();\n\n"
            "// AFTER (REMEDIATED):\n"
            "ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(\"com.example.SafeDTO;!*\"));\n"
            "Object obj = ois.readObject();"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
            "https://openjdk.org/jeps/290",
            "https://cwe.mitre.org/data/definitions/502.html"
        ]
    },

    "SEC-JV-005": {
        "title": "Upgrade Cryptographic Hash to SHA-256 / SHA-512 or Password Hashing API",
        "recommendation": (
            "Replace weak MessageDigest instances ('MD5', 'SHA-1') with 'SHA-256' or 'SHA-512'. "
            "For user passwords, use dedicated password hashing mechanisms like Argon2 or PBKDF2WithHmacSHA256."
        ),
        "corrected_code": (
            "import java.security.MessageDigest;\n"
            "import java.security.NoSuchAlgorithmException;\n"
            "import java.nio.charset.StandardCharsets;\n"
            "import java.util.HexFormat;\n\n"
            "public class CryptoUtils {\n"
            "    // Safe integrity checksum using SHA-256\n"
            "    public static String computeSha256(String input) throws NoSuchAlgorithmException {\n"
            "        MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n"
            "        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));\n"
            "        return HexFormat.of().formatHex(digest);\n"
            "    }\n"
            "}"
        ),
        "explanation": (
            "MD5 and SHA-1 have known collision vulnerabilities, allowing attackers to forge certificates "
            "and sign tampered files without changing the cryptographic hash."
        ),
        "best_practices": [
            "OWASP A02:2021 - Cryptographic Storage Cheat Sheet",
            "Use MessageDigest.getInstance(\"SHA-256\") at minimum",
            "For password hashing, use PBKDF2WithHmacSHA256 with high work factors or bcrypt/Argon2",
            "Use StandardCharsets.UTF_8 when converting strings to byte arrays"
        ],
        "diff_example": (
            "// BEFORE (VULNERABLE):\n"
            "// MessageDigest md = MessageDigest.getInstance(\"MD5\");\n\n"
            "// AFTER (REMEDIATED):\n"
            "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/327.html"
        ]
    },

    "SEC-JV-006": {
        "title": "Validate Path Normalization and Canonical Containment in Java",
        "recommendation": (
            "Resolve paths using java.nio.file.Path, normalize them, and verify that the target "
            "resides inside the designated base directory using Path.startsWith()."
        ),
        "corrected_code": (
            "import java.io.IOException;\n"
            "import java.nio.file.Path;\n"
            "import java.nio.file.Paths;\n\n"
            "public class SecureFileManager {\n"
            "    private final Path baseDir = Paths.get(\"/var/data/uploads\").toAbsolutePath().normalize();\n\n"
            "    public Path resolveSafePath(String untrustedFilename) throws IOException {\n"
            "        // 1. Strip path elements and resolve against base directory\n"
            "        Path target = baseDir.resolve(Paths.get(untrustedFilename).getFileName()).normalize();\n\n"
            "        // 2. Strict directory boundary verification\n"
            "        if (!target.startsWith(baseDir)) {\n"
            "            throw new SecurityException(\"Path traversal detected: Target path outside storage boundary.\");\n"
            "        }\n"
            "        return target;\n"
            "    }\n"
            "}"
        ),
        "explanation": (
            "Constructing new File(baseDir, userParam) does not block '../' sequences. Attackers "
            "traverse out of the storage directory to access system configuration files or overwrite libraries."
        ),
        "best_practices": [
            "OWASP A01:2021 - Path Traversal Prevention",
            "Use java.nio.file.Path and normalize()",
            "Verify canonical containment with target.startsWith(baseDir)",
            "Extract simple file names with getFileName() before resolving"
        ],
        "diff_example": (
            "// BEFORE (VULNERABLE):\n"
            "// File file = new File(uploadDir, userInput);\n\n"
            "// AFTER (REMEDIATED):\n"
            "Path target = baseDir.resolve(Paths.get(userInput).getFileName()).normalize();\n"
            "if (!target.startsWith(baseDir)) throw new SecurityException(\"Invalid path\");"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/22.html"
        ]
    },

    "SEC-JV-007": {
        "title": "Disable DTDs and External Entities in Java XML Parsers (XXE Prevention)",
        "recommendation": (
            "Configure DocumentBuilderFactory or SAXParserFactory with the 'disallow-doctype-decl' feature "
            "set to true and disable external general/parameter entities."
        ),
        "corrected_code": (
            "import javax.xml.parsers.DocumentBuilderFactory;\n"
            "import javax.xml.parsers.ParserConfigurationException;\n"
            "import javax.xml.XMLConstants;\n\n"
            "public class SafeXmlParser {\n"
            "    public static DocumentBuilderFactory createSecureFactory() throws ParserConfigurationException {\n"
            "        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
            "        // Prohibit DOCTYPE declarations entirely to prevent XXE\n"
            "        dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
            "        dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n"
            "        dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n"
            "        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, \"\");\n"
            "        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, \"\");\n"
            "        dbf.setXIncludeAware(false);\n"
            "        dbf.setExpandEntityReferences(false);\n"
            "        return dbf;\n"
            "    }\n"
            "}"
        ),
        "explanation": (
            "By default, older XML parsers resolve external entity references (SYSTEM \"file:///etc/passwd\"), "
            "allowing attackers submitting XML documents to read arbitrary server files or trigger SSRF."
        ),
        "best_practices": [
            "OWASP A05:2021 - XML External Entity Prevention Cheat Sheet",
            "Always set disallow-doctype-decl to true",
            "Disable external-general-entities and external-parameter-entities",
            "Use XMLConstants.FEATURE_SECURE_PROCESSING"
        ],
        "diff_example": (
            "// BEFORE (VULNERABLE):\n"
            "// DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n\n"
            "// AFTER (REMEDIATED):\n"
            "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
            "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);"
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/611.html"
        ]
    },

    # -------------------------------------------------------------
    # Code Quality, Smells, Complexity, and Anti-Patterns
    # -------------------------------------------------------------
    "SMELL-PY-001": {
        "title": "Refactor Long Function via Method Extraction",
        "recommendation": (
            "Break down lengthy functions exceeding 50 lines into smaller, focused helper functions. "
            "Adhere to the Single Responsibility Principle: each function should do one thing well."
        ),
        "corrected_code": (
            "# Refactored using Extract Method design pattern\n"
            "def process_order(order_data: dict) -> dict:\n"
            "    validated = validate_order_fields(order_data)\n"
            "    subtotal = calculate_subtotal(validated['items'])\n"
            "    discount = apply_promotions(subtotal, validated.get('promo_code'))\n"
            "    tax = compute_tax(subtotal - discount, validated['region'])\n"
            "    total = subtotal - discount + tax\n"
            "    return {'order_id': validated['id'], 'total': total, 'tax': tax}\n\n"
            "# Each sub-task is encapsulated into cohesive, testable helpers"
        ),
        "explanation": (
            "Long methods are difficult to comprehend, unit-test, and maintain. Decomposing them into "
            "small, well-named functions isolates logic, simplifies test coverage, and increases readability."
        ),
        "best_practices": [
            "Clean Code - Functions should do one thing and do it well",
            "Keep function lengths under 30-50 lines",
            "Give extracted helper functions clear, intention-revealing names"
        ],
        "diff_example": (
            "# BEFORE: A single 120-line monolithic function handling validation, db access, calculation, and notifications\n"
            "# AFTER: A coordinator function delegating to validate(), calculate(), and notify()"
        ),
        "references": ["https://refactoring.guru/smells/long-method"]
    },

    "SMELL-JV-001": {
        "title": "Decompose Long Java Method into Cohesive Helpers",
        "recommendation": (
            "Extract distinct operations into private helper methods within the class, or introduce "
            "collaborator classes for distinct concerns."
        ),
        "corrected_code": (
            "public class OrderProcessor {\n"
            "    public OrderResult process(OrderRequest request) {\n"
            "        validateRequest(request);\n"
            "        BigDecimal total = calculateTotal(request.getItems());\n"
            "        PaymentReceipt receipt = executePayment(request.getCustomerId(), total);\n"
            "        return new OrderResult(receipt.getTransactionId(), total, OrderStatus.COMPLETED);\n"
            "    }\n"
            "    private void validateRequest(OrderRequest req) { ... }\n"
            "    private BigDecimal calculateTotal(List<Item> items) { ... }\n"
            "}"
        ),
        "explanation": "Methods longer than 50 lines indicate multiple responsibilities and poor cohesion.",
        "best_practices": [
            "Single Responsibility Principle (SOLID)",
            "Aim for methods under 30 lines of code",
            "Improve testability through isolated unit testing of sub-methods"
        ],
        "diff_example": "// Break down large 80+ line methods into small private methods.",
        "references": ["https://refactoring.guru/smells/long-method"]
    },

    "SMELL-PY-002": {
        "title": "Consolidate Long Parameter List into a Dataclass or Parameter Object",
        "recommendation": (
            "Functions with more than 5 parameters create high cognitive load. Group related parameters "
            "into a typed dataclass, namedtuple, or configuration dictionary."
        ),
        "corrected_code": (
            "from dataclasses import dataclass\n"
            "from typing import Optional\n\n"
            "@dataclass(frozen=True)\n"
            "class UserRegistrationContext:\n"
            "    username: str\n"
            "    email: str\n"
            "    first_name: str\n"
            "    last_name: str\n"
            "    role: str = 'viewer'\n"
            "    phone_number: Optional[str] = None\n\n"
            "def register_user(ctx: UserRegistrationContext) -> str:\n"
            "    # Clean, maintainable signature passing a single cohesive context object\n"
            "    return f'Created user {ctx.username} <{ctx.email}> with role {ctx.role}'"
        ),
        "explanation": (
            "Long parameter lists are error-prone: callers easily transpose arguments of identical types. "
            "A Parameter Object groups related data and allows backwards-compatible extensions with default values."
        ),
        "best_practices": [
            "Use Python dataclasses for structured argument grouping",
            "Enforce type annotations on all dataclass fields",
            "Limit parameter counts to 3-4 arguments maximum"
        ],
        "diff_example": (
            "# BEFORE:\n"
            "# def create_account(name, email, age, street, city, state, zip_code, phone, role): ...\n\n"
            "# AFTER:\n"
            "# def create_account(info: AccountDetails, address: PostalAddress): ..."
        ),
        "references": ["https://refactoring.guru/smells/long-parameter-list"]
    },

    "SMELL-JV-002": {
        "title": "Use Builder Pattern or Parameter Object (DTO) in Java",
        "recommendation": (
            "Replace methods having > 5 parameters with a Java record, DTO class, or the Builder pattern."
        ),
        "corrected_code": (
            "public record UserProfileDto(\n"
            "    String username,\n"
            "    String email,\n"
            "    String firstName,\n"
            "    String lastName,\n"
            "    String department\n"
            ") {}\n\n"
            "public void registerUser(UserProfileDto profile) {\n"
            "    // Clean and cohesive method call\n"
            "}"
        ),
        "explanation": "Java methods with many parameters are hard to read and test.",
        "best_practices": [
            "Use Java 17+ records for immutable DTOs",
            "Use the Builder pattern for optional parameter construction",
            "Keep parameter lists to 3 or fewer where practical"
        ],
        "diff_example": "// Replace long method signature with record or builder.",
        "references": ["https://refactoring.guru/smells/long-parameter-list"]
    },

    "SMELL-PY-003": {
        "title": "Decompose Bloated Class Following Single Responsibility Principle",
        "recommendation": (
            "Classes exceeding 150 lines or 12 methods often act as God Classes. Divide them into "
            "smaller, cohesive classes that each manage a single domain responsibility."
        ),
        "corrected_code": (
            "# Split single bloated 'UserManager' into cohesive services:\n"
            "class UserAuthenticationService:\n"
            "    def authenticate(self, username: str, token: str) -> bool: ...\n\n"
            "class UserNotificationService:\n"
            "    def send_welcome_email(self, email: str) -> None: ...\n\n"
            "class UserRepository:\n"
            "    def save_user(self, user_data: dict) -> int: ..."
        ),
        "explanation": "Bloated classes violate high cohesion and make testing difficult.",
        "best_practices": [
            "Single Responsibility Principle (SRP)",
            "Favor composition over large inheritance hierarchies",
            "Keep class responsibilities focused"
        ],
        "diff_example": "# Split monolithic manager into focused, single-purpose classes.",
        "references": ["https://refactoring.guru/smells/large-class"]
    },

    "SMELL-PY-004": {
        "title": "Avoid Empty Exception Handlers (Pass / Silent Suppression)",
        "recommendation": (
            "Never silently swallow exceptions with 'except Exception: pass'. Log the exception "
            "with context using logger.exception() or logger.warning(), or handle specific expected errors."
        ),
        "corrected_code": (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n\n"
            "try:\n"
            "    result = parse_numeric_data(raw_value)\n"
            "except ValueError as exc:\n"
            "    logger.warning('Failed to parse numeric value %r: %s', raw_value, exc)\n"
            "    result = 0.0"
        ),
        "explanation": (
            "Silent exception suppression hides syntax errors, system failures, and database disconnections, "
            "making production bugs almost impossible to diagnose."
        ),
        "best_practices": [
            "Catch specific exceptions rather than broad BaseException",
            "Always log or raise caught exceptions",
            "Provide safe, documented fallback values when handling expected exceptions"
        ],
        "diff_example": (
            "# BEFORE (POOR PRACTICE):\n"
            "# try:\n"
            "#     do_work()\n"
            "# except Exception:\n"
            "#     pass\n\n"
            "# AFTER (REMEDIATED):\n"
            "try:\n"
            "    do_work()\n"
            "except SpecificError as err:\n"
            "    logger.error('Operation failed: %s', err)"
        ),
        "references": ["https://peps.python.org/pep-0008/#programming-recommendations"]
    },

    "SMELL-JV-004": {
        "title": "Avoid Empty Catch Blocks in Java",
        "recommendation": (
            "Never leave catch (Exception e) {} blocks empty. Log the error using a logger (SLF4J/Logback) "
            "or rethrow a domain-specific exception."
        ),
        "corrected_code": (
            "import org.slf4j.Logger;\n"
            "import org.slf4j.LoggerFactory;\n\n"
            "public class DataService {\n"
            "    private static final Logger log = LoggerFactory.getLogger(DataService.class);\n\n"
            "    public void loadCache() {\n"
            "        try {\n"
            "            performLoad();\n"
            "        } catch (IOException e) {\n"
            "            log.warn(\"Failed to load cache from disk: {}\", e.getMessage(), e);\n"
            "        }\n"
            "    }\n"
            "}"
        ),
        "explanation": "Empty catch blocks hide runtime bugs and data corruption.",
        "best_practices": [
            "Never use empty catch blocks",
            "Log with logger.error() including the exception object",
            "Catch specific exceptions instead of generic java.lang.Exception"
        ],
        "diff_example": "// Replace empty catch {} with proper logging or rethrow.",
        "references": ["https://rules.sonarsource.com/java/RSPEC-1166/"]
    },

    "SMELL-PY-005": {
        "title": "Replace Wildcard Imports (from module import *) with Explicit Imports",
        "recommendation": (
            "Replace wildcard imports with explicit imports of the specific functions, classes, "
            "or constants needed. Wildcard imports pollute the namespace and obscure origins."
        ),
        "corrected_code": (
            "# Explicit imports identify exactly what is being used\n"
            "from math import sqrt, pi, sin\n"
            "# Or import the module namespace:\n"
            "import math\n\n"
            "area = pi * (radius ** 2)"
        ),
        "explanation": (
            "Wildcard imports make it impossible for static analysis tools, linters, and developers "
            "to identify where a symbol was defined, and can lead to unexpected namespace collisions."
        ),
        "best_practices": [
            "PEP 8 - Wildcard imports should be avoided",
            "Explicitly list imported names",
            "Keep imports grouped: standard library, third-party, local"
        ],
        "diff_example": (
            "# BEFORE: from os.path import *\n"
            "# AFTER: from os.path import join, exists, basename"
        ),
        "references": ["https://peps.python.org/pep-0008/#imports"]
    },

    "COMPLEX-PY-001": {
        "title": "Reduce Cyclomatic Complexity via Guard Clauses or Strategy Pattern",
        "recommendation": (
            "High cyclomatic complexity indicates too many branching decision points (if/elif/while). "
            "Refactor using early return guard clauses, dictionary dispatch tables, or the Strategy pattern."
        ),
        "corrected_code": (
            "# Table-driven strategy dispatch replacing deep if-elif chains\n"
            "DISCOUNT_STRATEGIES = {\n"
            "    'VIP': lambda p: p * 0.80,\n"
            "    'GOLD': lambda p: p * 0.85,\n"
            "    'SILVER': lambda p: p * 0.90,\n"
            "    'STANDARD': lambda p: p\n"
            "}\n\n"
            "def calculate_discounted_price(price: float, tier: str) -> float:\n"
            "    strategy = DISCOUNT_STRATEGIES.get(tier.upper(), DISCOUNT_STRATEGIES['STANDARD'])\n"
            "    return round(strategy(price), 2)"
        ),
        "explanation": (
            "Methods with cyclomatic complexity > 8 require exponentially more test cases to achieve full branch "
            "coverage and are significantly more prone to regression defects."
        ),
        "best_practices": [
            "Target cyclomatic complexity under 6-8 per function",
            "Use guard clauses (return early) to flatten branch trees",
            "Replace long conditional ladders with dictionary dispatch"
        ],
        "diff_example": "# Replace nested if/elif/else ladders with strategy lookup tables.",
        "references": ["https://en.wikipedia.org/wiki/Cyclomatic_complexity"]
    },

    "COMPLEX-PY-002": {
        "title": "Flatten Deep Nesting with Early Return Guard Clauses",
        "recommendation": (
            "Nesting code deeper than 3-4 levels (the Arrow Anti-Pattern) obscures control flow. "
            "Invert conditions and return early to flatten function bodies."
        ),
        "corrected_code": (
            "def process_transaction(user, account, amount) -> bool:\n"
            "    # Guard clause 1: validate user\n"
            "    if not user or not user.is_active:\n"
            "        return False\n\n"
            "    # Guard clause 2: validate account\n"
            "    if not account or account.is_frozen:\n"
            "        return False\n\n"
            "    # Guard clause 3: validate balance\n"
            "    if account.balance < amount:\n"
            "        return False\n\n"
            "    # Core business logic kept at base indentation level\n"
            "    account.debit(amount)\n"
            "    return True"
        ),
        "explanation": "Deep nesting makes code difficult to trace and increases mental overhead.",
        "best_practices": [
            "Use early returns to eliminate else branches",
            "Keep indentation depth <= 2 levels",
            "Extract inner loop bodies into standalone helper functions"
        ],
        "diff_example": (
            "# BEFORE: if a: if b: if c: if d: do_work()\n"
            "# AFTER: if not a: return; if not b: return; do_work()"
        ),
        "references": ["https://refactoring.guru/flattening-nested-conditionals"]
    },

    "DESIGN-PY-001": {
        "title": "Eliminate Mutable Default Arguments in Function Signatures",
        "recommendation": (
            "Default arguments in Python are evaluated once when the function is defined, not on every call. "
            "Never use mutable default arguments like [] or {}. Default to None and initialize inside the function."
        ),
        "corrected_code": (
            "from typing import Optional, List\n\n"
            "def append_item(item: str, target_list: Optional[List[str]] = None) -> List[str]:\n"
            "    # Correct idiom: initialize new list on each invocation if None was passed\n"
            "    if target_list is None:\n"
            "        target_list = []\n"
            "    target_list.append(item)\n"
            "    return target_list"
        ),
        "explanation": (
            "Because Python evaluates default expressions once at function definition time, all calls "
            "omitting the argument share the identical list/dict instance in memory, creating subtle bugs."
        ),
        "best_practices": [
            "Always default optional mutable containers to None",
            "Initialize new container inside the function body if arg is None",
            "Use typing.Optional[List[...]] type annotations"
        ],
        "diff_example": (
            "# BEFORE (DEFECTIVE):\n"
            "# def add_user(user, users=[]): users.append(user); return users\n\n"
            "# AFTER (REMEDIATED):\n"
            "def add_user(user, users=None):\n"
            "    if users is None: users = []\n"
            "    users.append(user)\n"
            "    return users"
        ),
        "references": ["https://docs.python-guide.org/writing/gotchas/#mutable-default-arguments"]
    },

    "DESIGN-PY-004": {
        "title": "Replace Magic Numbers with Intention-Revealing Named Constants",
        "recommendation": (
            "Extract raw literal numbers embedded in logic into descriptive UPPER_CASE module constants."
        ),
        "corrected_code": (
            "# Descriptive module constants\n"
            "MAX_RETRY_ATTEMPTS = 3\n"
            "REQUEST_TIMEOUT_SECONDS = 30\n"
            "HTTP_STATUS_RATE_LIMITED = 429\n\n"
            "def fetch_remote_resource():\n"
            "    for attempt in range(MAX_RETRY_ATTEMPTS):\n"
            "        ...\n"
        ),
        "explanation": (
            "Magic numbers obscure the author's intent and make changes error-prone if the same value "
            "is duplicated across multiple locations."
        ),
        "best_practices": [
            "Define module-level constants in UPPER_SNAKE_CASE",
            "Document unit of measure if applicable (e.g. TIMEOUT_SECONDS, SIZE_BYTES)",
            "Group related constants in Enums"
        ],
        "diff_example": "# Replace 'if days > 86400' with 'if seconds > SECONDS_PER_DAY'",
        "references": ["https://refactoring.guru/replace-magic-number-with-symbolic-constant"]
    },

    "PRACTICE-PY-001": {
        "title": "Replace print() with Configured Structured Logging",
        "recommendation": (
            "Replace print() calls with standard logging module calls (logging.getLogger(__name__)). "
            "Logging provides timestamps, log levels, output redirection, and filterability."
        ),
        "corrected_code": (
            "import logging\n\n"
            "logger = logging.getLogger(__name__)\n\n"
            "def process_job(job_id: str) -> None:\n"
            "    # Structured logging with level and interpolation\n"
            "    logger.info('Processing job %s started.', job_id)\n"
            "    try:\n"
            "        ...\n"
            "    except Exception:\n"
            "        logger.exception('Job %s failed during processing.', job_id)"
        ),
        "explanation": (
            "print() statements write to standard output without level categorization, context, or timestamps. "
            "They cannot be dynamically disabled in production environments without code modification."
        ),
        "best_practices": [
            "Use logger = logging.getLogger(__name__)",
            "Choose appropriate levels: debug, info, warning, error, critical",
            "Use lazy string formatting (%s) in logger calls for performance"
        ],
        "diff_example": (
            "# BEFORE: print('User logged in: ' + username)\n"
            "# AFTER: logger.info('User %s authenticated successfully', username)"
        ),
        "references": ["https://docs.python.org/3/library/logging.html"]
    },

    "PRACTICE-JV-001": {
        "title": "Replace System.out.println with SLF4J / Logback Logging in Java",
        "recommendation": (
            "Replace System.out.println and printStackTrace() with an SLF4J Logger."
        ),
        "corrected_code": (
            "import org.slf4j.Logger;\n"
            "import org.slf4j.LoggerFactory;\n\n"
            "public class PaymentService {\n"
            "    private static final Logger log = LoggerFactory.getLogger(PaymentService.class);\n\n"
            "    public void recordPayment(String transactionId) {\n"
            "        log.info(\"Recording payment for transaction {}\", transactionId);\n"
            "    }\n"
            "}"
        ),
        "explanation": "System.out cannot be dynamically filtered and slows down application threads.",
        "best_practices": [
            "Use SLF4J facade with Logback implementation",
            "Use parameterized logging log.info(\"User: {}\", user)",
            "Avoid e.printStackTrace() in production"
        ],
        "diff_example": "// Replace System.out.println with log.info()",
        "references": ["https://www.slf4j.org/manual.html"]
    },

    "PRACTICE-PY-002": {
        "title": "Manage File and Network Resources Using 'with' Context Managers",
        "recommendation": (
            "Always wrap file I/O and network streams in 'with' statement context managers to guarantee "
            "file descriptors are closed promptly, even when exceptions are raised."
        ),
        "corrected_code": (
            "def read_configuration_file(filepath: str) -> str:\n"
            "    # Context manager guarantees file is closed automatically upon leaving block\n"
            "    with open(filepath, 'r', encoding='utf-8') as f:\n"
            "        return f.read()"
        ),
        "explanation": (
            "Unclosed file descriptors remain open until garbage collected. On high-throughput servers, "
            "leaked file descriptors trigger 'Too many open files' OS errors (errno 24)."
        ),
        "best_practices": [
            "Always use 'with open(...) as f:' for file operations",
            "Specify explicit encoding='utf-8' on text files",
            "Use contextlib.closing for objects that have close() but no __enter__"
        ],
        "diff_example": (
            "# BEFORE:\n"
            "# f = open('data.txt')\n"
            "# content = f.read()\n\n"
            "# AFTER:\n"
            "with open('data.txt', 'r', encoding='utf-8') as f:\n"
            "    content = f.read()"
        ),
        "references": ["https://docs.python.org/3/reference/compound_stmts.html#with"]
    },

    "PRACTICE-JV-002": {
        "title": "Use Try-With-Resources for Automatic Resource Management in Java",
        "recommendation": (
            "Wrap AutoCloseable resources (streams, connections, readers) in try-with-resources statements."
        ),
        "corrected_code": (
            "import java.io.BufferedReader;\n"
            "import java.io.FileReader;\n"
            "import java.io.IOException;\n\n"
            "public class FileReaderUtil {\n"
            "    public static String readFile(String path) throws IOException {\n"
            "        // Automatic resource closure guaranteed\n"
            "        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {\n"
            "            return reader.readLine();\n"
            "        }\n"
            "    }\n"
            "}"
        ),
        "explanation": "Try-with-resources prevents resource leaks and simplifies error handling.",
        "best_practices": [
            "Always use try-with-resources for AutoCloseable classes",
            "Eliminate manual .close() calls in finally blocks"
        ],
        "diff_example": "// Replace try { ... } finally { in.close(); } with try (in) { ... }",
        "references": ["https://docs.oracle.com/javase/tutorial/essential/exceptions/tryResourceClose.html"]
    },

    # -------------------------------------------------------------
    # Context-Aware Risky Call Exception Rules
    # -------------------------------------------------------------
    "RISK-PY-001": {
        "title": "Configure Explicit Timeout on Python Network Operations",
        "recommendation": (
            "Always specify an explicit timeout parameter (e.g. timeout=5.0 or timeout=(3.05, 10.0)) "
            "when invoking network operations like requests.get() or requests.post(). "
            "Without an explicit timeout, requests will block indefinitely if the remote server fails to respond, "
            "exhausting thread pools and causing denial of service."
        ),
        "corrected_code": (
            "import requests\n\n"
            "# Configured with explicit connect (3.05s) and read (10.0s) timeouts:\n"
            "try:\n"
            "    response = requests.get('https://api.example.com/data', timeout=(3.05, 10.0))\n"
            "    response.raise_for_status()\n"
            "    data = response.json()\n"
            "except requests.exceptions.Timeout:\n"
            "    logger.error('Request timed out connecting to upstream service')\n"
            "except requests.exceptions.RequestException as err:\n"
            "    logger.error(f'Network error: {err}')"
        ),
        "explanation": (
            "Network calls without timeouts are vulnerable to CWE-400 (Uncontrolled Resource Consumption). "
            "If an external server drops packets or hangs, client threads remain locked in I/O wait, "
            "ultimately crashing web workers or microservices."
        ),
        "best_practices": [
            "OWASP A05:2021 - Security Misconfiguration / Denial of Service Prevention",
            "Always pass a timeout float or tuple to requests calls",
            "Implement circuit breakers and retries with exponential backoff",
            "Set appropriate connection and read timeouts based on SLA"
        ],
        "diff_example": (
            "# BEFORE (VULNERABLE):\n"
            "# resp = requests.get(url)\n\n"
            "# AFTER (REMEDIATED):\n"
            "resp = requests.get(url, timeout=5.0)"
        ),
        "references": [
            "https://requests.readthedocs.io/en/latest/user/advanced/#timeouts",
            "https://cwe.mitre.org/data/definitions/400.html"
        ]
    },

    "RISK-PY-002": {
        "title": "Handle Network-Specific Exceptions with Proper Try-Except Block",
        "recommendation": (
            "Wrap all outbound network and socket operations in explicit try-except blocks handling "
            "requests.exceptions.RequestException, socket.error, or urllib.error.URLError. "
            "Avoid letting raw socket errors bubble up to unhandled server crashes."
        ),
        "corrected_code": (
            "import requests\n"
            "import logging\n\n"
            "logger = logging.getLogger(__name__)\n\n"
            "def fetch_remote_resource(url: str):\n"
            "    try:\n"
            "        resp = requests.get(url, timeout=5.0)\n"
            "        resp.raise_for_status()\n"
            "        return resp.json()\n"
            "    except requests.exceptions.HTTPError as err:\n"
            "        logger.error(f'HTTP error: {err}')\n"
            "    except requests.exceptions.ConnectionError as err:\n"
            "        logger.error(f'Connection failed: {err}')\n"
            "    except requests.exceptions.Timeout as err:\n"
            "        logger.error(f'Request timed out: {err}')\n"
            "    except requests.exceptions.RequestException as err:\n"
            "        logger.error(f'General network exception: {err}')\n"
            "    return None"
        ),
        "explanation": (
            "Outbound network calls fail unpredictably due to DNS resolution errors, dropped packets, "
            "TLS handshake failures, and server restarts. Without robust error handling, an unhandled "
            "exception terminates process threads and degrades application availability."
        ),
        "best_practices": [
            "Catch requests.RequestException as the base network exception",
            "Differentiate between timeouts, HTTP client errors, and connection drops",
            "Log structured error telemetry for production monitoring"
        ],
        "diff_example": (
            "# BEFORE:\n"
            "# return requests.get(url, timeout=5).json()\n\n"
            "# AFTER:\n"
            "try:\n"
            "    return requests.get(url, timeout=5).json()\n"
            "except requests.exceptions.RequestException as e:\n"
            "    logger.error('Failed to fetch: %s', e)\n"
            "    return None"
        ),
        "references": [
            "https://requests.readthedocs.io/en/latest/user/quickstart/#errors-and-exceptions",
            "https://cwe.mitre.org/data/definitions/755.html"
        ]
    },

    "RISK-PY-003": {
        "title": "Enclose Database Operations in Robust Error Handlers with Transaction Rollback",
        "recommendation": (
            "Ensure all database queries, updates, and transaction commits are wrapped in try-except blocks "
            "catching database-specific errors (e.g. sqlite3.Error, psycopg2.Error). Ensure that on failure, "
            "conn.rollback() is invoked to avoid hanging locks or corrupted transactional state."
        ),
        "corrected_code": (
            "import sqlite3\n"
            "import logging\n\n"
            "def update_account_balance(conn: sqlite3.Connection, account_id: int, delta: float):\n"
            "    try:\n"
            "        cursor = conn.cursor()\n"
            "        cursor.execute('UPDATE accounts SET balance = balance + ? WHERE id = ?', (delta, account_id))\n"
            "        conn.commit()\n"
            "        return True\n"
            "    except sqlite3.Error as err:\n"
            "        conn.rollback()\n"
            "        logging.error(f'Database transaction failed: {err}')\n"
            "        return False"
        ),
        "explanation": (
            "If a database operation fails midway through an open transaction, unhandled exceptions "
            "leave the transaction open or inconsistent, holding table/row locks and risking partial writes."
        ),
        "best_practices": [
            "Always call rollback() in exception blocks during transaction handling",
            "Use context managers: with conn: conn.execute(...) automatically commits or rolls back",
            "Catch specific database exception hierarchies instead of broad Exception"
        ],
        "diff_example": (
            "# BEFORE:\n"
            "# cursor.execute(query, params)\n"
            "# conn.commit()\n\n"
            "# AFTER:\n"
            "try:\n"
            "    cursor.execute(query, params)\n"
            "    conn.commit()\n"
            "except sqlite3.Error:\n"
            "    conn.rollback()\n"
            "    raise"
        ),
        "references": [
            "https://docs.python.org/3/library/sqlite3.html#using-the-connection-as-a-context-manager",
            "https://cwe.mitre.org/data/definitions/755.html"
        ]
    },

    "RISK-JV-001": {
        "title": "Manage JDBC Connection and Statements within Try-with-Resources",
        "recommendation": (
            "Enclose JDBC Connection, PreparedStatement, and ResultSet instances within a try-with-resources statement. "
            "Never create database connections as raw unmanaged local variables without guaranteed deterministic closure."
        ),
        "corrected_code": (
            "import java.sql.Connection;\n"
            "import java.sql.DriverManager;\n"
            "import java.sql.PreparedStatement;\n"
            "import java.sql.ResultSet;\n"
            "import java.sql.SQLException;\n\n"
            "public class DatabaseHelper {\n"
            "    public void queryUserData(String url, String user, String pass, int userId) throws SQLException {\n"
            "        String sql = \"SELECT id, username FROM users WHERE id = ?\";\n"
            "        try (Connection conn = DriverManager.getConnection(url, user, pass);\n"
            "             PreparedStatement pstmt = conn.prepareStatement(sql)) {\n"
            "            pstmt.setInt(1, userId);\n"
            "            try (ResultSet rs = pstmt.executeQuery()) {\n"
            "                while (rs.next()) {\n"
            "                    System.out.println(rs.getString(\"username\"));\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}"
        ),
        "explanation": (
            "Failing to close JDBC resources leads to database connection pool exhaustion (CWE-404 / CWE-775), "
            "rendering the entire backend application incapable of serving subsequent user requests."
        ),
        "best_practices": [
            "Use try-with-resources for all AutoCloseable JDBC objects",
            "Nest ResultSets or chain them within the try resource specification",
            "Use connection pooling libraries (HikariCP) in enterprise applications"
        ],
        "diff_example": (
            "// BEFORE:\n"
            "// Connection conn = DriverManager.getConnection(url);\n"
            "// Statement stmt = conn.createStatement();\n\n"
            "// AFTER:\n"
            "try (Connection conn = DriverManager.getConnection(url);\n"
            "     Statement stmt = conn.createStatement()) {\n"
            "    // Safe execution\n"
            "}"
        ),
        "references": [
            "https://docs.oracle.com/javase/tutorial/essential/exceptions/tryResourceClose.html",
            "https://cwe.mitre.org/data/definitions/404.html"
        ]
    },

    "RISK-JV-002": {
        "title": "Configure Connect and Read Timeouts on Java Network Connections",
        "recommendation": (
            "Always call setConnectTimeout(int ms) and setReadTimeout(int ms) on HttpURLConnection or Socket "
            "instances before connecting. The default Java timeout is 0 (infinite wait), which will hang threads."
        ),
        "corrected_code": (
            "import java.net.URL;\n"
            "import java.net.HttpURLConnection;\n"
            "import java.io.InputStream;\n\n"
            "public class SafeHttpClient {\n"
            "    public static InputStream fetchUrl(String endpoint) throws Exception {\n"
            "        URL url = new URL(endpoint);\n"
            "        HttpURLConnection conn = (HttpURLConnection) url.openConnection();\n"
            "        // Enforce explicit network timeouts to prevent thread hanging:\n"
            "        conn.setConnectTimeout(5000); // 5 seconds connect timeout\n"
            "        conn.setReadTimeout(10000);   // 10 seconds read timeout\n"
            "        conn.setRequestMethod(\"GET\");\n"
            "        return conn.getInputStream();\n"
            "    }\n"
            "}"
        ),
        "explanation": (
            "In Java, HttpURLConnection and Socket have default connection and read timeouts of 0 (infinite). "
            "If an external peer server fails to acknowledge packets, the calling Java thread remains blocked "
            "indefinitely, rapidly exhausting thread pools and causing full application denial of service (CWE-400)."
        ),
        "best_practices": [
            "Always set both connectTimeout and readTimeout on every outbound connection",
            "Use modern Java HTTP Client (java.net.http.HttpClient) with HttpRequest.Builder.timeout()",
            "Catch SocketTimeoutException specifically to differentiate from connection refused"
        ],
        "diff_example": (
            "// BEFORE:\n"
            "// HttpURLConnection conn = (HttpURLConnection) url.openConnection();\n"
            "// conn.connect();\n\n"
            "// AFTER:\n"
            "HttpURLConnection conn = (HttpURLConnection) url.openConnection();\n"
            "conn.setConnectTimeout(5000);\n"
            "conn.setReadTimeout(10000);\n"
            "conn.connect();"
        ),
        "references": [
            "https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/URLConnection.html#setConnectTimeout(int)",
            "https://cwe.mitre.org/data/definitions/400.html"
        ]
    }
}


class RemediationAgent:
    """
    Remediation Agent:
    Generates specific, production-ready fix recommendations with corrected code examples,
    step-by-step guidance, and best practice explanations for every flagged code inspection finding.
    """

    def __init__(self):
        self.name = AGENT_NAME

    def _generate_fallback_remediation(self, finding: Dict[str, Any], language: str) -> Dict[str, Any]:
        """Generate a safe, high-quality generic remediation when rule is not in the pre-defined catalog."""
        rule_id = str(finding.get("rule_id", "GENERIC-001"))
        title = str(finding.get("title", "Code Issue"))
        category = str(finding.get("category", "Code Quality"))
        evidence = str(finding.get("evidence", "")).strip()
        mitigation = str(finding.get("mitigation", "")).strip()
        risk = str(finding.get("risk_explanation", "")).strip()
        line = finding.get("line", 1)

        is_python = language.lower() == "python"

        if is_python:
            sample_fix = (
                f"# Remediated pattern for {rule_id}:\n"
                f"# Ensure proper input validation, resource scoping, and exception handling:\n"
                f"def safe_operation():\n"
                f"    # Review line {line}: replace '{evidence[:40]}...' with validated, secure logic\n"
                f"    pass"
            )
        else:
            sample_fix = (
                f"// Remediated pattern for {rule_id}:\n"
                f"// Ensure strict type safety, resource management, and parameter validation:\n"
                f"public void safeOperation() {{\n"
                f"    // Review line {line}: refactor '{evidence[:40]}...' into safe implementation\n"
                f"}}"
            )

        recommendation_text = mitigation if mitigation else (
            f"Review the flagged code at line {line}. Refactor to address {category.lower()} guidelines: "
            f"ensure proper parameter validation, robust error handling, and clean code principles."
        )

        return {
            "finding_id": f"{rule_id}:{line}",
            "rule_id": rule_id,
            "title": f"Remediate: {title}",
            "recommendation": recommendation_text,
            "corrected_code": sample_fix,
            "explanation": risk if risk else f"Addresses the {category} violation identified by {rule_id}.",
            "best_practices": [
                f"Follow standard {language.title()} secure coding and clean code conventions",
                "Perform strict input and boundary validation",
                "Ensure resources and exceptions are managed deterministically"
            ],
            "diff_example": f"// Before: {evidence}\n// After: See corrected pattern above",
            "references": finding.get("owasp_references", [])
        }

    def generate_remediation(
        self,
        finding: Dict[str, Any],
        source_code: Optional[str] = None,
        language: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate a complete remediation object for a single finding.
        Returns title, recommendation, corrected code, explanation, best practices, and diff.
        """
        rule_id = str(finding.get("rule_id", "")).strip()
        lang = (language or finding.get("language") or "python").strip().lower()

        # Check catalog
        catalog_entry = REMEDIATION_CATALOG.get(rule_id)

        if catalog_entry:
            remediation = {
                "finding_id": f"{rule_id}:{finding.get('line', 0)}",
                "rule_id": rule_id,
                "title": catalog_entry["title"],
                "recommendation": catalog_entry["recommendation"],
                "corrected_code": catalog_entry["corrected_code"],
                "explanation": catalog_entry["explanation"],
                "best_practices": list(catalog_entry["best_practices"]),
                "diff_example": catalog_entry["diff_example"],
                "references": list(catalog_entry.get("references", []))
            }
            # Merge with finding's specific owasp_references if present
            if finding.get("owasp_references"):
                for ref in finding["owasp_references"]:
                    if ref not in remediation["references"]:
                        remediation["references"].append(ref)
            return remediation

        return self._generate_fallback_remediation(finding, lang)

    def enrich_finding(
        self,
        finding: Dict[str, Any],
        source_code: Optional[str] = None,
        language: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enriches an existing finding dictionary with a 'remediation' field
        containing specific fix recommendations and corrected code examples.
        """
        enriched = dict(finding)
        remediation_data = self.generate_remediation(
            finding=finding,
            source_code=source_code,
            language=language
        )
        enriched["remediation"] = remediation_data
        # Also ensure top-level mitigation field is enriched if empty
        if not enriched.get("mitigation"):
            enriched["mitigation"] = remediation_data["recommendation"]
        return enriched

    def enrich_findings(
        self,
        findings: List[Dict[str, Any]],
        source_code: Optional[str] = None,
        language: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Batch-enrich a list of findings with remediation guidance."""
        return [
            self.enrich_finding(f, source_code=source_code, language=language)
            for f in findings
        ]


# Singleton instance
_remediation_agent = RemediationAgent()


def get_remediation_agent() -> RemediationAgent:
    return _remediation_agent

